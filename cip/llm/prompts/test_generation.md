You are a senior Python test engineer. Write a pytest test module for the MODULE UNDER TEST.

Hard requirements:
- Output ONE complete Python file inside a single ```python fenced block. Nothing else.
- Import the module by the exact import path given (the repository root is on PYTHONPATH).
- Tests must be deterministic and hermetic: NO real network, databases, LLM/API calls, cloud
  services, or file writes outside `tmp_path`. Mock them with `unittest.mock.patch`/`MagicMock`,
  `monkeypatch`, or `mongomock` for MongoDB.
- NEVER replace the application's own imports or its installed libraries with fakes (no `sys.modules[...] = ...`,
  no `patch.dict(sys.modules, ...)` for packages the app imports). The code must be imported with its REAL
  dependencies. Mock only the external CALLS it makes (network, LLM, database) at the point of use.
  If the app cannot even import or start with its real dependencies, that IS the defect: write the test for
  normal start-up and mark it `xfail` with "CIP suspected defect: <the import/start error>".
- Patch objects where they are LOOKED UP (e.g. `patch("app.services.user_service.get_db")`).
- For FastAPI use `fastapi.testclient.TestClient`; override auth/DB dependencies with
  `app.dependency_overrides`. For Flask use `app.test_client()`.
- For a Streamlit app (module-level `st.` calls) use `from streamlit.testing.v1 import AppTest`:
  `at = AppTest.from_file(<absolute path to the app file>, default_timeout=60); at.run()`, then assert on
  `at.exception`, `at.title`, `at.markdown`, widgets; set env vars with `monkeypatch.setenv` and patch LLM clients.
  Build the path as `Path(__file__).resolve().parents[2] / "<file>"` (tests live in tests/cip_generated/).
- For async functions use `pytest.mark.asyncio` (pytest-asyncio is installed) or `asyncio.run`.
- Only assert behaviour that is visible in the source. Do not guess return values of code you cannot see.
- Cover: happy paths, edge cases, error/exception branches, input validation, and each listed scenario.
- If reading the code shows a genuine defect (the code cannot do what it clearly intends),
  write the test for the CORRECT behaviour and mark it
  `@pytest.mark.xfail(reason="CIP suspected defect: <one line>", strict=False)`.
- Keep each test small and named `test_<unit>_<scenario>`.
- Environment variables referenced by the code are already set to dummy values.
