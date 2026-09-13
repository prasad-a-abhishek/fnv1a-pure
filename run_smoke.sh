#!/bin/bash
set -e
rm -rf /tmp/fnv1a-venv-smoke
python3 -m venv /tmp/fnv1a-venv-smoke
/tmp/fnv1a-venv-smoke/bin/pip install -q -e /root/projects/fnv1a-pure/.worktrees/t_cycle71-build
/tmp/fnv1a-venv-smoke/bin/python -c "
from fnv1a_pure import fnv1a_64, fnv1a_32
assert fnv1a_64(b'') == 14695981039346656037, 'empty 64'
assert fnv1a_64(b'a') == 12638187200555641996, 'a 64'
assert fnv1a_64(b'hello') == 11831194018420276491, 'hello 64'
assert fnv1a_32(b'hello') == 1335831723, 'hello 32'
print('smoke OK')
"
