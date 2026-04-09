// ©AngelaMos | 2026
// pass.rs
//
// Analysis pass trait, pass manager, and topological execution
//
// Defines the AnalysisPass trait (sealed via a private module
// to prevent external implementations) with name(),
// dependencies(), and run() methods. PassManager accepts a
// Vec of boxed passes, computes a topological execution order
// via Kahn's algorithm (panics on cycles), and run_all()
// executes them in dependency order, continuing through
// failures and recording each PassOutcome with timing and
// error info. PassReport aggregates outcomes with
// all_succeeded() and failed_passes() query methods.
// Includes unit tests using MockPass to verify topological
// ordering, diamond dependencies, failure continuation,
// cycle detection, and duration tracking.
//
// Connects to:
//   context.rs - AnalysisContext (passed to each pass)
//   error.rs   - EngineError (returned by pass::run)

use std::collections::{HashMap, VecDeque};
use std::time::Instant;

use crate::context::AnalysisContext;
use crate::error::EngineError;

mod private {
    pub trait Sealed {}
}

pub trait AnalysisPass: private::Sealed + Send + Sync {
    fn name(&self) -> &'static str;
    fn dependencies(&self) -> &[&'static str];
    fn run(
        &self,
        ctx: &mut AnalysisContext,
    ) -> Result<(), EngineError>;
}

#[derive(Debug, Clone)]
pub struct PassOutcome {
    pub name: &'static str,
    pub success: bool,
    pub duration_ms: u64,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PassReport {
    pub outcomes: Vec<PassOutcome>,
}

impl PassReport {
    pub fn all_succeeded(&self) -> bool {
        self.outcomes.iter().all(|o| o.success)
    }

    pub fn failed_passes(&self) -> Vec<&PassOutcome> {
        self.outcomes
            .iter()
            .filter(|o| !o.success)
            .collect()
    }
}

pub struct PassManager {
    passes: Vec<Box<dyn AnalysisPass>>,
    order: Vec<usize>,
}

impl PassManager {
    pub fn new(
        passes: Vec<Box<dyn AnalysisPass>>,
    ) -> Self {
        let order = topological_order(&passes);
        Self { passes, order }
    }

    pub fn run_all(
        &self,
        ctx: &mut AnalysisContext,
    ) -> PassReport {
        let mut outcomes = Vec::with_capacity(self.passes.len());

        for &idx in &self.order {
            let pass = &self.passes[idx];
            let start = Instant::now();
            let result = pass.run(ctx);
            let duration_ms =
                start.elapsed().as_millis() as u64;

            let outcome = match result {
                Ok(()) => {
                    tracing::info!(
                        pass = pass.name(),
                        duration_ms,
                        "pass completed"
                    );
                    PassOutcome {
                        name: pass.name(),
                        success: true,
                        duration_ms,
                        error_message: None,
                    }
                }
                Err(e) => {
                    tracing::error!(
                        pass = pass.name(),
                        error = %e,
                        duration_ms,
                        "pass failed"
                    );
                    PassOutcome {
                        name: pass.name(),
                        success: false,
                        duration_ms,
                        error_message: Some(e.to_string()),
                    }
                }
            };

            outcomes.push(outcome);
        }

        PassReport { outcomes }
    }
}

fn topological_order(
    passes: &[Box<dyn AnalysisPass>],
) -> Vec<usize> {
    let name_to_idx: HashMap<&str, usize> = passes
        .iter()
        .enumerate()
        .map(|(i, p)| (p.name(), i))
        .collect();

    let n = passes.len();
    let mut in_degree = vec![0usize; n];
    let mut adjacency: Vec<Vec<usize>> = vec![vec![]; n];

    for (idx, pass) in passes.iter().enumerate() {
        for dep_name in pass.dependencies() {
            if let Some(&dep_idx) = name_to_idx.get(dep_name)
            {
                adjacency[dep_idx].push(idx);
                in_degree[idx] += 1;
            }
        }
    }

    let mut queue: VecDeque<usize> = in_degree
        .iter()
        .enumerate()
        .filter(|&(_, deg)| *deg == 0)
        .map(|(i, _)| i)
        .collect();

    let mut order = Vec::with_capacity(n);

    while let Some(node) = queue.pop_front() {
        order.push(node);
        for &neighbor in &adjacency[node] {
            in_degree[neighbor] -= 1;
            if in_degree[neighbor] == 0 {
                queue.push_back(neighbor);
            }
        }
    }

    assert_eq!(
        order.len(),
        n,
        "cycle detected in pass dependencies — this is a programmer error"
    );

    order
}

pub(crate) use private::Sealed;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct MockPass {
        name: &'static str,
        deps: Vec<&'static str>,
        log: Arc<Mutex<Vec<&'static str>>>,
        should_fail: bool,
    }

    impl Sealed for MockPass {}

    impl AnalysisPass for MockPass {
        fn name(&self) -> &'static str {
            self.name
        }

        fn dependencies(&self) -> &[&'static str] {
            &self.deps
        }

        fn run(
            &self,
            _ctx: &mut AnalysisContext,
        ) -> Result<(), EngineError> {
            self.log.lock().unwrap().push(self.name);
            if self.should_fail {
                return Err(EngineError::PassFailed {
                    pass: self.name,
                    source: "mock failure".into(),
                });
            }
            Ok(())
        }
    }

    fn make_ctx() -> AnalysisContext {
        AnalysisContext::new(
            crate::context::BinarySource::Buffered(
                Arc::from(vec![0u8; 4]),
            ),
            "deadbeef".into(),
            "test.bin".into(),
            4,
        )
    }

    #[test]
    fn topological_sort_respects_dependencies() {
        let log = Arc::new(Mutex::new(Vec::new()));

        let passes: Vec<Box<dyn AnalysisPass>> = vec![
            Box::new(MockPass {
                name: "c",
                deps: vec!["b"],
                log: Arc::clone(&log),
                should_fail: false,
            }),
            Box::new(MockPass {
                name: "a",
                deps: vec![],
                log: Arc::clone(&log),
                should_fail: false,
            }),
            Box::new(MockPass {
                name: "b",
                deps: vec!["a"],
                log: Arc::clone(&log),
                should_fail: false,
            }),
        ];

        let manager = PassManager::new(passes);
        let mut ctx = make_ctx();
        let report = manager.run_all(&mut ctx);

        let execution_order = log.lock().unwrap().clone();
        assert_eq!(execution_order, vec!["a", "b", "c"]);
        assert!(report.all_succeeded());
        assert_eq!(report.outcomes.len(), 3);
    }

    #[test]
    fn continues_on_failure() {
        let log = Arc::new(Mutex::new(Vec::new()));

        let passes: Vec<Box<dyn AnalysisPass>> = vec![
            Box::new(MockPass {
                name: "first",
                deps: vec![],
                log: Arc::clone(&log),
                should_fail: false,
            }),
            Box::new(MockPass {
                name: "second",
                deps: vec![],
                log: Arc::clone(&log),
                should_fail: true,
            }),
            Box::new(MockPass {
                name: "third",
                deps: vec![],
                log: Arc::clone(&log),
                should_fail: false,
            }),
        ];

        let manager = PassManager::new(passes);
        let mut ctx = make_ctx();
        let report = manager.run_all(&mut ctx);

        let execution_order = log.lock().unwrap().clone();
        assert_eq!(
            execution_order,
            vec!["first", "second", "third"]
        );
        assert!(!report.all_succeeded());
        assert_eq!(report.failed_passes().len(), 1);
        assert_eq!(
            report.failed_passes()[0].name,
            "second"
        );
    }

    #[test]
    fn diamond_dependency_ordering() {
        let log = Arc::new(Mutex::new(Vec::new()));

        let passes: Vec<Box<dyn AnalysisPass>> = vec![
            Box::new(MockPass {
                name: "score",
                deps: vec!["imports", "entropy"],
                log: Arc::clone(&log),
                should_fail: false,
            }),
            Box::new(MockPass {
                name: "entropy",
                deps: vec!["format"],
                log: Arc::clone(&log),
                should_fail: false,
            }),
            Box::new(MockPass {
                name: "format",
                deps: vec![],
                log: Arc::clone(&log),
                should_fail: false,
            }),
            Box::new(MockPass {
                name: "imports",
                deps: vec!["format"],
                log: Arc::clone(&log),
                should_fail: false,
            }),
        ];

        let manager = PassManager::new(passes);
        let mut ctx = make_ctx();
        manager.run_all(&mut ctx);

        let order = log.lock().unwrap().clone();
        let format_pos =
            order.iter().position(|&n| n == "format").unwrap();
        let imports_pos =
            order.iter().position(|&n| n == "imports").unwrap();
        let entropy_pos =
            order.iter().position(|&n| n == "entropy").unwrap();
        let score_pos =
            order.iter().position(|&n| n == "score").unwrap();

        assert!(format_pos < imports_pos);
        assert!(format_pos < entropy_pos);
        assert!(imports_pos < score_pos);
        assert!(entropy_pos < score_pos);
    }

    #[test]
    #[should_panic(expected = "cycle detected")]
    fn detects_cycle() {
        let log = Arc::new(Mutex::new(Vec::new()));

        let passes: Vec<Box<dyn AnalysisPass>> = vec![
            Box::new(MockPass {
                name: "a",
                deps: vec!["b"],
                log: Arc::clone(&log),
                should_fail: false,
            }),
            Box::new(MockPass {
                name: "b",
                deps: vec!["a"],
                log: Arc::clone(&log),
                should_fail: false,
            }),
        ];

        let _manager = PassManager::new(passes);
    }

    #[test]
    fn reports_duration() {
        let log = Arc::new(Mutex::new(Vec::new()));

        let passes: Vec<Box<dyn AnalysisPass>> = vec![
            Box::new(MockPass {
                name: "fast",
                deps: vec![],
                log: Arc::clone(&log),
                should_fail: false,
            }),
        ];

        let manager = PassManager::new(passes);
        let mut ctx = make_ctx();
        let report = manager.run_all(&mut ctx);

        assert_eq!(report.outcomes.len(), 1);
        assert_eq!(report.outcomes[0].name, "fast");
        assert!(report.outcomes[0].success);
    }
}
