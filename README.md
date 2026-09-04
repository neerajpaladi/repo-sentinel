# repo-sentinel

## Workflow
1. User submits a GitHub repository URL.
2. API receives the request and creates a unique workflow_id.
3. Workflow Manager initializes shared state for that workflow.
4. Repository Acquisition layer accesses the repository using controlled GitHub/API access.
5. The repository is copied into an isolated read-only/working environment.
6. The original GitHub repository is never modified during autonomous analysis.
7. Planner Agent examines the objective and available repository information.
8. Planner creates the initial execution plan.
9. Orchestrator receives the plan and begins executing tasks.
10. Orchestrator selects the appropriate agent for each task:
    1. Code Agent uses controlled tools such as GitHub APIs and repository-analysis tools.
    2. OSINT Agent investigates relevant public information.
    3. Security Agent analyzes the repository's security posture.
    4. Correlation/Risk Agent combines the findings from the different agents.
11. Results are returned to the Planner and decides whether additional investigation is necessary.