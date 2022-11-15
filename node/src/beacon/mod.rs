// Copyright (C) 2019-2022 Aleo Systems Inc.
// This file is part of the snarkOS library.

// The snarkOS library is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// The snarkOS library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with the snarkOS library. If not, see <https://www.gnu.org/licenses/>.

mod router;

use crate::traits::NodeInterface;
use snarkos_account::Account;
use snarkos_node_consensus::Consensus;
use snarkos_node_executor::{spawn_task_loop, Executor, NodeType, Status};
use snarkos_node_ledger::{Ledger, RecordMap};
use snarkos_node_messages::{
    Data,
    Message,
    PuzzleResponse,
    UnconfirmedBlock,
    UnconfirmedSolution,
    UnconfirmedTransaction,
};
use snarkos_node_rest::Rest;
use snarkos_node_router::{Handshake, Inbound, Outbound, Router, RouterRequest};
use snarkos_node_store::ConsensusDB;
use snarkvm::prelude::{
    Address,
    Block,
    Identifier,
    Network,
    PrivateKey,
    ProgramID,
    ProverSolution,
    Transaction,
    Value,
    ViewKey,
    Zero,
};

use anyhow::{bail, Result};
use core::{str::FromStr, time::Duration};
use parking_lot::RwLock;
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
};
use time::OffsetDateTime;
use tokio::time::timeout;

/// A beacon is a full node, capable of producing blocks.
#[derive(Clone)]
pub struct Beacon<N: Network> {
    /// The account of the node.
    account: Account<N>,
    /// The consensus module of the node.
    consensus: Consensus<N, ConsensusDB<N>>,
    /// The ledger of the node.
    ledger: Ledger<N, ConsensusDB<N>>,
    /// The router of the node.
    router: Router<N>,
    /// The REST server of the node.
    rest: Option<Arc<Rest<N, ConsensusDB<N>>>>,
    /// The time it to generate a block.
    block_generation_time: Arc<AtomicU64>,
    /// The unspent records.
    unspent_records: Arc<RwLock<RecordMap<N>>>,
    /// The shutdown signal.
    shutdown: Arc<AtomicBool>,
}

impl<N: Network> Beacon<N> {
    /// Initializes a new beacon node.
    pub async fn new(
        node_ip: SocketAddr,
        rest_ip: Option<SocketAddr>,
        private_key: PrivateKey<N>,
        trusted_peers: &[SocketAddr],
        genesis: Option<Block<N>>,
        dev: Option<u16>,
    ) -> Result<Self> {
        // Initialize the node account.
        let account = Account::from(private_key)?;
        // Initialize the ledger.
        let ledger = Ledger::load(genesis, dev)?;
        // Initialize the consensus.
        let consensus = Consensus::new(ledger.clone())?;
        // Initialize the node router.
        let (router, router_receiver) = Router::new::<Self>(node_ip, account.address(), trusted_peers).await?;
        // Initialize the REST server.
        let rest = match rest_ip {
            Some(rest_ip) => Some(Arc::new(Rest::start(
                rest_ip,
                account.address(),
                Some(consensus.clone()),
                ledger.clone(),
                router.clone(),
            )?)),
            None => None,
        };
        // Initialize the block generation time.
        let block_generation_time = Arc::new(AtomicU64::new(2));
        // Retrieve the unspent records.
        let unspent_records = ledger.find_unspent_records(account.view_key())?;
        // Initialize the node.
        let node = Self {
            account,
            consensus,
            ledger,
            router: router.clone(),
            rest,
            block_generation_time,
            unspent_records: Arc::new(RwLock::new(unspent_records)),
            shutdown: Default::default(),
        };
        // Initialize the router handler.
        router.initialize_handler(node.clone(), router_receiver).await;

        // Initialize the block production.
        node.initialize_block_production().await;
        // Initialize the signal handler.
        node.handle_signals();
        // Return the node.
        Ok(node)
    }

    /// Returns the ledger.
    pub fn ledger(&self) -> &Ledger<N, ConsensusDB<N>> {
        &self.ledger
    }

    /// Returns the REST server.
    pub fn rest(&self) -> &Option<Arc<Rest<N, ConsensusDB<N>>>> {
        &self.rest
    }
}

#[async_trait]
impl<N: Network> Executor for Beacon<N> {
    /// The node type.
    const NODE_TYPE: NodeType = NodeType::Beacon;

    /// Disconnects from peers and shuts down the node.
    async fn shut_down(&self) {
        info!("Shutting down...");
        // Update the node status.
        Self::status().update(Status::ShuttingDown);

        // Shut down the ledger.
        trace!("Proceeding to shut down the ledger...");
        self.shutdown.store(true, Ordering::SeqCst);

        // Flush the tasks.
        Self::resources().shut_down();
        trace!("Node has shut down.");
    }
}

impl<N: Network> NodeInterface<N> for Beacon<N> {
    /// Returns the node type.
    fn node_type(&self) -> NodeType {
        Self::NODE_TYPE
    }

    /// Returns the node router.
    fn router(&self) -> &Router<N> {
        &self.router
    }

    /// Returns the account private key of the node.
    fn private_key(&self) -> &PrivateKey<N> {
        self.account.private_key()
    }

    /// Returns the account view key of the node.
    fn view_key(&self) -> &ViewKey<N> {
        self.account.view_key()
    }

    /// Returns the account address of the node.
    fn address(&self) -> Address<N> {
        self.account.address()
    }
}

/// A helper method to check if the coinbase target has been met.
async fn check_for_coinbase<N: Network>(consensus: Consensus<N, ConsensusDB<N>>) {
    loop {
        // Check if the coinbase target has been met.
        match consensus.is_coinbase_target_met() {
            Ok(true) => break,
            Ok(false) => (),
            Err(error) => error!("Failed to check if coinbase target is met: {error}"),
        }
        // Sleep for one second.
        tokio::time::sleep(Duration::from_secs(1)).await
    }
}

impl<N: Network> Beacon<N> {
    /// Initialize a new instance of block production.
    async fn initialize_block_production(&self) {
        let beacon = self.clone();
        spawn_task_loop!(Self, {
            // Expected time per block.
            const ROUND_TIME: u64 = 15; // 15 seconds per block

            // Produce blocks.
            loop {
                // Fetch the current timestamp.
                let current_timestamp = OffsetDateTime::now_utc().unix_timestamp();
                // Compute the elapsed time.
                let elapsed_time = current_timestamp.saturating_sub(beacon.ledger.latest_timestamp()) as u64;

                // Do not produce a block if the elapsed time has not exceeded `ROUND_TIME - block_generation_time`.
                // This will ensure a block is produced at intervals of approximately `ROUND_TIME`.
                let time_to_wait = ROUND_TIME.saturating_sub(beacon.block_generation_time.load(Ordering::SeqCst));
                trace!("Waiting for {time_to_wait} seconds before producing a block...");
                if elapsed_time < time_to_wait {
                    if let Err(error) = timeout(
                        Duration::from_secs(time_to_wait.saturating_sub(elapsed_time)),
                        check_for_coinbase(beacon.consensus.clone()),
                    )
                    .await
                    {
                        trace!("Check for coinbase - {error}");
                    }
                }

                // Start a timer.
                let timer = std::time::Instant::now();
                // Produce the next block and propagate it to all peers.
                match beacon.produce_next_block().await {
                    // Update the block generation time.
                    Ok(()) => beacon.block_generation_time.store(timer.elapsed().as_secs(), Ordering::SeqCst),
                    Err(error) => error!("{error}"),
                }

                // If the Ctrl-C handler registered the signal, stop the node once the current block is complete.
                if beacon.shutdown.load(Ordering::Relaxed) {
                    info!("Shutting down block production");
                    break;
                }
            }
        });
    }

    /// Produces the next block and propagates it to all peers.
    async fn produce_next_block(&self) -> Result<()> {
        let mut beacon_transaction: Option<Transaction<N>> = None;

        // Produce a transaction if the mempool is empty.
        if self.consensus.memory_pool().num_unconfirmed_transactions() == 0 {
            // Create a transfer transaction.
            let beacon = self.clone();
            let transaction = match tokio::task::spawn_blocking(move || {
                // Fetch an unspent record.
                let (commitment, record) = match beacon.unspent_records.write().shift_remove_index(0) {
                    Some(record) => record,
                    None => bail!("The beacon has no unspent records available"),
                };

                // Initialize an RNG.
                let rng = &mut rand::thread_rng();

                // Prepare the inputs.
                let to = beacon.account.address();
                let amount = 1;
                let inputs = [
                    Value::Record(record.clone()),
                    Value::from_str(&format!("{to}"))?,
                    Value::from_str(&format!("{amount}u64"))?,
                ];

                // Create a new transaction.
                let transaction = Transaction::execute(
                    beacon.ledger.vm(),
                    beacon.account.private_key(),
                    ProgramID::from_str("credits.aleo")?,
                    Identifier::from_str("transfer")?,
                    inputs.iter(),
                    None,
                    None,
                    rng,
                );

                match transaction {
                    Ok(transaction) => Ok(transaction),
                    Err(error) => {
                        // Push the record back into the unspent records.
                        beacon.unspent_records.write().insert(commitment, record);
                        bail!("Failed to create a transaction: {error}")
                    }
                }
            })
            .await
            {
                Ok(Ok(transaction)) => transaction,
                Ok(Err(error)) => bail!("Failed to create a transfer transaction for the next block: {error}"),
                Err(error) => bail!("Failed to create a transfer transaction for the next block: {error}"),
            };
            // Save the beacon transaction.
            beacon_transaction = Some(transaction.clone());

            // Add the transaction to the memory pool.
            let beacon = self.clone();
            match tokio::task::spawn_blocking(move || beacon.consensus.add_unconfirmed_transaction(transaction)).await {
                Ok(Ok(())) => (),
                Ok(Err(error)) => bail!("Failed to add the transaction to the memory pool: {error}"),
                Err(error) => bail!("Failed to add the transaction to the memory pool: {error}"),
            }
        }

        // Propose the next block.
        let beacon = self.clone();
        let next_block = match tokio::task::spawn_blocking(move || {
            let next_block = beacon.consensus.propose_next_block(beacon.private_key(), &mut rand::thread_rng())?;

            // Ensure the block is a valid next block.
            if let Err(error) = beacon.consensus.check_next_block(&next_block) {
                // Clear the memory pool of all solutions and transactions.
                trace!("Clearing the memory pool...");
                beacon.consensus.clear_memory_pool()?;
                trace!("Cleared the memory pool");
                bail!("Proposed an invalid block: {error}")
            }

            // Advance to the next block.
            match beacon.consensus.advance_to_next_block(&next_block) {
                Ok(()) => {
                    // If the beacon produced a transaction, save its output records.
                    if let Some(transaction) = beacon_transaction {
                        // Save the unspent records.
                        if let Err(error) = transaction.into_transitions().try_for_each(|transition| {
                            for (commitment, record) in transition.into_records() {
                                let record = record.decrypt(beacon.account.view_key())?;
                                if !record.gates().is_zero() {
                                    beacon.unspent_records.write().insert(commitment, record);
                                }
                            }
                            Ok::<_, anyhow::Error>(())
                        }) {
                            warn!("Unable to save the beacon unspent records, recomputing unspent records: {error}");
                            // Recompute the unspent records.
                            *beacon.unspent_records.write() =
                                beacon.ledger.find_unspent_records(beacon.account.view_key())?;
                        };
                    }
                    // Log the next block.
                    match serde_json::to_string_pretty(&next_block.header()) {
                        Ok(header) => info!("Block {}: {header}", next_block.height()),
                        Err(error) => info!("Block {}: (serde failed: {error})", next_block.height()),
                    }
                }
                Err(error) => {
                    // Clear the memory pool of all solutions and transactions.
                    trace!("Clearing the memory pool...");
                    beacon.consensus.clear_memory_pool()?;
                    trace!("Cleared the memory pool");
                    bail!("Failed to advance to the next block: {error}")
                }
            }

            Ok(next_block)
        })
        .await
        {
            Ok(Ok(next_block)) => next_block,
            Ok(Err(error)) => {
                // Sleep for one second.
                tokio::time::sleep(Duration::from_secs(1)).await;
                bail!("Failed to propose the next block: {error}")
            }
            Err(error) => {
                // Sleep for one second.
                tokio::time::sleep(Duration::from_secs(1)).await;
                bail!("Failed to propose the next block (JoinError): {error}")
            }
        };
        let next_block_height = next_block.height();
        let next_block_hash = next_block.hash();

        // // Ensure the block is a valid next block.
        // if let Err(error) = self.consensus.check_next_block(&next_block) {
        //     // Clear the memory pool of all solutions and transactions.
        //     trace!("Clearing the memory pool...");
        //     self.consensus.clear_memory_pool()?;
        //     trace!("Cleared the memory pool");
        //     // Sleep for one second.
        //     tokio::time::sleep(Duration::from_secs(1)).await;
        //     bail!("Proposed an invalid block: {error}")
        // }
        //
        // // Advance to the next block.
        // match self.consensus.advance_to_next_block(&next_block) {
        //     Ok(()) => match serde_json::to_string_pretty(&next_block.header()) {
        //         Ok(header) => info!("Block {next_block_height}: {header}"),
        //         Err(error) => info!("Block {next_block_height}: (serde failed: {error})"),
        //     },
        //     Err(error) => {
        //         // Clear the memory pool of all solutions and transactions.
        //         trace!("Clearing the memory pool...");
        //         self.consensus.clear_memory_pool()?;
        //         trace!("Cleared the memory pool");
        //         // Sleep for one second.
        //         tokio::time::sleep(Duration::from_secs(1)).await;
        //         bail!("Failed to advance to the next block: {error}")
        //     }
        // }

        // Serialize the block ahead of time to not do it for each peer.
        let serialized_block = match Data::Object(next_block).serialize().await {
            Ok(serialized_block) => serialized_block,
            Err(error) => bail!("Failed to serialize the next block for propagation: {error}"),
        };

        // Prepare the block to be sent to all peers.
        let message = Message::<N>::UnconfirmedBlock(UnconfirmedBlock {
            block_height: next_block_height,
            block_hash: next_block_hash,
            block: Data::Buffer(serialized_block),
        });

        // Propagate the block to all peers.
        if let Err(error) = self.router.process(RouterRequest::MessagePropagate(message, vec![])).await {
            trace!("Failed to broadcast the next block: {error}");
        }

        Ok(())
    }
}
