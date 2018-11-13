TESTS=tests/

check:
	## No unused imports, no undefined vars, no line length
	flake8 --exclude __init__.py --ignore=E731,W503,E501 --max-complexity 10 pingscan/

pylint:

	pylint --rcfile .pylintrc pingscan/

typecheck:

	mypy --ignore-missing-imports -p pingscan

test:

	python -m pytest -v $(TESTS)

coverage:

	python -m pytest --cov pingscan --cov-report term-missing $(TESTS)

prcheck:

	check pylint coverage

safety:

	safety check
