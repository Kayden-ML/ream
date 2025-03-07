#[macro_export]
macro_rules! test_sanity_block {
    ($processing_fn:path, $operation_object:ty) => {
        paste::paste! {
            #[cfg(test)]
            #[allow(non_snake_case)]
            mod tests_sanity {
                use super::*;
                use ream_consensus::execution_engine::mock_engine::MockExecutionEngine;
                use std::{fs, path::{Path, PathBuf}, sync::Arc};
                use tokio::sync::Mutex;
                use serde_yaml;

                #[derive(Debug, serde::Deserialize)]
                struct MetaData {
                    blocks_count: usize,
                    bls_setting: Option<usize>,
                }

                #[tokio::test]
                async fn test_sanity_block() {
                    let base_path = std::env::current_dir().unwrap().join("mainnet/tests/mainnet/deneb/sanity/blocks/pyspec_tests");
                    println!("Base path: {:?}", base_path);
                    
                    for entry in std::fs::read_dir(&base_path).unwrap() {
                        let entry = entry.unwrap();
                        let case_dir = entry.path();
                        if !case_dir.is_dir() {
                            continue;
                        }
                        
                        let case_name = case_dir.file_name().unwrap().to_str().unwrap();
                        println!("Testing case: {}", case_name);

                        // Read and parse meta.yaml
                        let meta: MetaData = {
                            let meta_path = case_dir.join("meta.yaml");
                            let content = fs::read_to_string(meta_path)
                                .expect("Failed to read meta.yaml");
                            serde_yaml::from_str(&content).expect("Failed to parse meta.yaml")
                        };
                        println!("Blocks count: {}, BLS setting: {:?}", meta.blocks_count, meta.bls_setting);

                        let pre_state: Arc<Mutex<BeaconState>> = Arc::new(Mutex::new(
                            utils::read_ssz_snappy(&case_dir.join("pre.ssz_snappy"))
                                .expect("cannot find test asset(pre.ssz_snappy)"),
                        ));

                        let mock_engine = MockExecutionEngine {
                            execution_valid: true,
                        };

                        let validate_result = true;

                        let mut state = pre_state.clone();

                        for i in 0..meta.blocks_count {
                            let block_path = case_dir.join(format!("blocks_{}.ssz_snappy", i));
                            if !block_path.exists() {
                                panic!("Test asset not found: {:?}", block_path);
                            } else {
                                println!("Found test asset: {:?}", block_path);
                            }
                        
                            let signed_block: SignedBeaconBlock = utils::read_ssz_snappy(&block_path)
                                .expect(&format!("cannot find test asset (blocks_{}.ssz_snappy)", i));
                        
                            println!("Decoded SignedBeaconBlock: {:?}", signed_block);
                            
                            state.lock().await.state_transition(signed_block, validate_result)
                                .expect("Block processing failed");
                        }
                        

                        let input: $operation_object =
                            utils::read_ssz_snappy(&case_dir.join("input.ssz_snappy"))
                                .expect("cannot find test asset (input.ssz_snappy)");

                        let expected_post = utils::read_ssz_snappy::<BeaconState>(&case_dir.join("post.ssz_snappy"));

                        let result = state.lock().await.$processing_fn(&input, &mock_engine).await;

                        match (result, expected_post) {
                            (Ok(_), Ok(expected)) => {
                                let locked_state = state.lock().await;
                                assert_eq!(*locked_state, expected, "Post state mismatch in case {}", case_name);
                            }
                            (Ok(_), Err(_)) => {
                                panic!("Test case {} should have failed but succeeded", case_name);
                            }
                            (Err(err), Ok(_)) => {
                                panic!("Test case {} should have succeeded but failed, err={:?}", case_name, err);
                            }
                            (Err(_), Err(_)) => {
                                // Expected: invalid operations result in an error and no post state.
                            }
                        }
                    }
                }
            }
        }
    };
}
