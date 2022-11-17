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
use snarkos_node_executor::{spawn_task, spawn_task_loop, Executor, NodeType, Status};
use snarkos_node_messages::{Data, Message, PuzzleResponse, UnconfirmedSolution};
use snarkos_node_router::{Handshake, Inbound, Outbound, Router, RouterRequest};
use snarkvm::prelude::{Address, Block, CoinbasePuzzle, EpochChallenge, Network, PrivateKey, ProverSolution, ViewKey};

use anyhow::Result;
use core::time::Duration;
use rand::Rng;
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU32, AtomicU8},
        Arc,
    },
};
use time::OffsetDateTime;
use tokio::sync::RwLock;

/// A prover is a full node, capable of producing proofs for consensus.
#[derive(Clone)]
pub struct Prover<N: Network> {
    /// The account of the node.
    account: Account<N>,
    /// The router of the node.
    router: Router<N>,
    /// The coinbase puzzle.
    coinbase_puzzle: CoinbasePuzzle<N>,
    /// The latest epoch challenge.
    latest_epoch_challenge: Arc<RwLock<Option<EpochChallenge<N>>>>,
    /// The latest block.
    latest_block: Arc<RwLock<Option<Block<N>>>>,
    /// The number of puzzle instances.
    puzzle_instances: Arc<AtomicU8>,

    solutions_prove: Arc<AtomicU32>,
    solutions_found: Arc<AtomicU32>,
}

impl<N: Network> Prover<N> {
    /// Initializes a new prover node.
    pub async fn new(node_ip: SocketAddr, private_key: PrivateKey<N>, trusted_peers: &[SocketAddr]) -> Result<Self> {
        // Initialize the node account.
        let account = Account::from(private_key)?;
        // Initialize the node router.
        let (router, router_receiver) = Router::new::<Self>(node_ip, account.address(), trusted_peers).await?;
        // Load the coinbase puzzle.
        let coinbase_puzzle = CoinbasePuzzle::<N>::load()?;
        // Initialize the node.
        let node = Self {
            account,
            router: router.clone(),
            coinbase_puzzle,
            latest_epoch_challenge: Default::default(),
            latest_block: Default::default(),
            puzzle_instances: Default::default(),

            solutions_prove: Default::default(),
            solutions_found: Default::default(),
        };
        // Initialize the router handler.
        router.initialize_handler(node.clone(), router_receiver).await;
        // Initialize the coinbase puzzle.
        node.initialize_coinbase_puzzle().await;
        // Initialize the signal handler.
        node.handle_signals();

        let prover = node.clone();
        spawn_task_loop!(Self, {
            use colored::*;

            let mut status = std::collections::VecDeque::<u32>::from(vec![0; 60]);
            let mut timer_count = 0;
            loop {
                let new = prover.solutions_prove.load(std::sync::atomic::Ordering::SeqCst);
                if new > 0 {
                    if timer_count % (60 / 2) == 0 {
                        status.pop_front();
                        status.push_back(new);
                    }

                    let mut pps = String::from("");
                    for i in [1, 5, 15, 30, 60] {
                        let old = status.get(60 - i).unwrap_or(&0);
                        let rate = (new - *old) as f64 / (i * 60) as f64;
                        if rate > 0.8 {
                            pps.push_str(format!("{}m: {:.2} s/s, ", i, rate).as_str());
                        } else {
                            pps.push_str(format!("{}m: --- s/s, ", i).as_str());
                        }
                    }

                    let found = prover.solutions_found.load(std::sync::atomic::Ordering::SeqCst);
                    info!("{}", format!("Found solutions/proved solutions {found}/{new}, {pps}").cyan().bold());

                    timer_count += 1;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        });

        // Return the node.
        Ok(node)
    }
}

#[async_trait]
impl<N: Network> Executor for Prover<N> {
    /// The node type.
    const NODE_TYPE: NodeType = NodeType::Prover;
}

impl<N: Network> NodeInterface<N> for Prover<N> {
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

impl<N: Network> Prover<N> {
    /// Initialize a new instance of the coinbase puzzle.
    async fn initialize_coinbase_puzzle(&self) {
        let prover = self.clone();
        spawn_task_loop!(Self, {
            loop {
                // If the node is not connected to any peers, then skip this iteration.
                if prover.router.number_of_connected_peers().await == 0 {
                    warn!("Skipping an iteration of the prover solution (no connected peers)");
                    tokio::time::sleep(Duration::from_secs(N::ANCHOR_TIME as u64)).await;
                    continue;
                }

                // If the latest block timestamp exceeds a multiple of the anchor time, then skip this iteration.
                if let Some(latest_block) = prover.latest_block.read().await.as_ref() {
                    // Compute the elapsed time since the latest block.
                    let elapsed = OffsetDateTime::now_utc().unix_timestamp().saturating_sub(latest_block.timestamp());
                    // If the elapsed time exceeds a multiple of the anchor time, then skip this iteration.
                    if elapsed > N::ANCHOR_TIME as i64 * 6 {
                        warn!("Skipping an iteration of the prover solution (latest block is stale)");
                        // Send a "PuzzleRequest" to a beacon node.
                        prover.router.send_puzzle_request(prover.node_type()).await;
                        // Sleep for `N::ANCHOR_TIME` seconds.
                        tokio::time::sleep(Duration::from_secs(N::ANCHOR_TIME as u64)).await;
                        continue;
                    }
                }

                let prover = prover.clone();
                spawn_task!(Self, {
                    // Set the status to `Proving`.
                    Self::status().update(Status::Proving);
                    // Increment the number of puzzle instances.
                    prover.puzzle_instances.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

                    loop {
                        // Read the latest epoch challenge.
                        let latest_epoch_challenge = prover.latest_epoch_challenge.read().await.clone();
                        // Read the latest block.
                        let latest_block = prover.latest_block.read().await.clone();

                        // If the latest epoch challenge and latest block exists, then generate a prover solution.
                        if let (Some(epoch_challenge), Some(block)) = (latest_epoch_challenge, latest_block) {
                            // Retrieve the latest coinbase target.
                            let _latest_coinbase_target = block.coinbase_target();
                            // Retrieve the latest proof target.
                            let latest_proof_target = block.proof_target();

                            // debug!(
                            //     "Proving 'CoinbasePuzzle' (Epoch {}, Block {}, Coinbase Target {}, Proof Target {})",
                            //     epoch_challenge.epoch_number(),
                            //     block.height(),
                            //     latest_coinbase_target,
                            //     latest_proof_target,
                            // );

                            prover.solutions_prove.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

                            // Construct a prover solution.
                            let prover_solution = match prover.coinbase_puzzle.prove(
                                &epoch_challenge,
                                prover.address(),
                                rand::thread_rng().gen(),
                                Some(latest_proof_target),
                            ) {
                                Ok(proof) => proof,
                                Err(error) => {
                                    trace!("{error}");
                                    break;
                                }
                            };

                            // Fetch the prover solution target.
                            let prover_solution_target = match prover_solution.to_target() {
                                Ok(target) => target,
                                Err(error) => {
                                    warn!("Failed to fetch prover solution target: {error}");
                                    break;
                                }
                            };

                            // Ensure that the prover solution target is sufficient.
                            match prover_solution_target >= latest_proof_target {
                                true => {
                                    info!("Found a Solution (Proof Target {prover_solution_target})");

                                    // Propagate the "UnconfirmedSolution" to the network.
                                    let message = Message::UnconfirmedSolution(UnconfirmedSolution {
                                        puzzle_commitment: prover_solution.commitment(),
                                        solution: Data::Object(prover_solution),
                                    });
                                    let request = RouterRequest::MessagePropagate(message, vec![]);
                                    if let Err(error) = prover.router.process(request).await {
                                        warn!("[UnconfirmedSolution] {error}");
                                    }

                                    break;
                                }
                                false => trace!(
                                    "Prover solution was below the necessary proof target ({prover_solution_target} < {latest_proof_target})"
                                ),
                            }
                        } else {
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    }

                    // Set the status to `Ready`.
                    Self::status().update(Status::Ready);
                    // Decrement the number of puzzle instances.
                    prover.puzzle_instances.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    // Sleep briefly to give this instance a chance to clear state.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                });
            }
        });
    }
}
