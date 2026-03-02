//! Scenario runner – execute scripted flows from YAML files.

use crate::commands::CommandRegistry;
use crate::context::AppContext;
use crate::probes;
use crate::types::*;
/// Load a scenario from a YAML string.
pub fn load_scenario(yaml: &str) -> Result<Scenario, String> {
    serde_yaml::from_str(yaml).map_err(|e| format!("failed to parse scenario YAML: {}", e))
}

/// Execute a scenario and return the overall result.
pub async fn run_scenario(
    scenario: &Scenario,
    ctx: &AppContext,
    registry: &CommandRegistry,
) -> ScenarioResult {
    let mut step_results = Vec::new();
    let mut overall = Status::Pass;

    for (i, step) in scenario.steps.iter().enumerate() {
        let result = match step {
            ScenarioStep::Call {
                call,
                args,
                expect_status,
                timeout_ms: _timeout_ms,
            } => {
                // TODO: honour timeout_ms with tokio::time::timeout
                let r = registry.execute(call, args.clone(), ctx);
                // Check expectation
                let actual_status = serde_json::to_value(r.status)
                    .ok()
                    .and_then(|v| v.as_str().map(String::from))
                    .unwrap_or_default();
                if actual_status != *expect_status {
                    tracing::warn!(
                        step = i,
                        expected = %expect_status,
                        actual = %actual_status,
                        "scenario step status mismatch"
                    );
                    overall = Status::Fail;
                }
                r
            }
            ScenarioStep::Probe { probe } => {
                let r = probes::run_probe(probe, ctx).await;
                if r.status != Status::Pass && r.status != Status::Skip {
                    overall = Status::Fail;
                }
                r
            }
        };
        step_results.push(result);
    }

    ScenarioResult {
        name: scenario.name.clone(),
        overall_status: overall,
        step_results,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_scenario() {
        let yaml = r#"
name: basic test
steps:
  - call: "ping"
    args: {}
    expect_status: "pass"
    timeout_ms: 5000
  - probe: "filesystem"
"#;
        let s = load_scenario(yaml).expect("should parse");
        assert_eq!(s.name, Some("basic test".into()));
        assert_eq!(s.steps.len(), 2);
    }

    #[tokio::test]
    async fn test_run_scenario_ping() {
        let yaml = r#"
steps:
  - call: "ping"
    args: {}
    expect_status: "pass"
"#;
        let scenario = load_scenario(yaml).unwrap();
        let ctx = AppContext::default_headless();
        let reg = CommandRegistry::new();
        let result = run_scenario(&scenario, &ctx, &reg).await;
        assert_eq!(result.overall_status, Status::Pass);
        assert_eq!(result.step_results.len(), 1);
    }

    #[test]
    fn test_parse_scenario_minimal() {
        let yaml = r#"
steps:
  - call: "read_file"
    args:
      path: "/tmp/nope"
"#;
        let s = load_scenario(yaml).expect("should parse");
        assert_eq!(s.steps.len(), 1);
    }
}
