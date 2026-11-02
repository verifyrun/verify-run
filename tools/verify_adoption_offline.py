"""Source-tree compatibility entry; prefer python -I -m vfy.offline_adoption_consumer."""
from vfy.offline_adoption_consumer import main

if __name__ == '__main__':
    raise SystemExit(main())
