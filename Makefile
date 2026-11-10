.PHONY: test run report
run:
	SENTINEL_DEMO_MODE=1 uvicorn app.main:app --host 127.0.0.1 --port 8000
test:
	python -m pytest tests -q
report:
	python scripts/build_report.py