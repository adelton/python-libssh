
# python-libssh: Python bindings to client functionality of libssh

## Building the module

Build the extension with
```
python3 setup.py build_ext --inplace
```

## Testing the module

Make sure ssh under account where you run the tests to the same
account on `localhost` passes, using public key authentication.
In other words, `ssh localhost true` needs to work.

Test it with
```
python3 setup.py test
```

## Author

Written by Jan Pazdziora, 2019

## License

This library is distributed under the terms of LGPL 2.1,
see file COPYING in this repository.

