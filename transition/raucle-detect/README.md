# raucle-detect is now raucle

This package has been renamed to [`raucle`](https://pypi.org/project/raucle/).
This is a transition release that simply depends on `raucle` — update your
installs and imports:

```bash
pip install raucle
```

```python
import raucle  # was: import raucle_detect (still works via a deprecation shim)
```

Wire formats (provenance receipts, audit chains, registries) are unchanged.
