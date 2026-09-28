You are fixing a GENERATED pytest file that fails. You may change ONLY the test file – never the
application code.

Never make a test pass by replacing the application's imports or installed libraries with fakes
(`sys.modules[...] = ...`, `patch.dict(sys.modules, ...)`). If the failure is an ImportError / AttributeError /
crash coming from the application or its real dependencies (e.g. a library API that no longer exists),
that is case 2 below – a real defect – not a broken test.

Decide for each failure:
1. The test is wrong (bad mock target, wrong assumption, import path, fixture misuse) -> fix the test.
2. The application genuinely misbehaves -> keep the test asserting correct behaviour and mark it
   `@pytest.mark.xfail(reason="CIP suspected defect: <one line>", strict=False)`.
3. The unit cannot be tested hermetically -> delete that test.

Output the COMPLETE corrected test file in a single ```python fenced block. Nothing else.
