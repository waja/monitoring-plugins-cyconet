# nagios-plugin-check_wireguard

Nagios check for wireguard server

This plugin uses the `wg show` output on a Wireguard server to show the interfaces and peers defined

## Dependencies

* Monitoring::Plugin::Functions Perl module
* Monitoring::Plugin::Getopt Perl module

## Usage
```
./check_wireguard
```

The output shows the following information
```
WIREGUARD OK Interfaces: Online:2 Expected:2 wg0:1/2 wg1:0/2
```

* `Interfaces: Online:X Expected:Y` The number of interfaces found with `wg show` and the number expected (provided by the `-i` argument)
* The available online interfaces are then listed in the format `wgX:<connected>/<total>`.
    * `<connected>` is the number of interfaces that have a "latest handshake" value listed
    * `<total>` is the total number of peers defined for that interface

## Installation

* Copy the `check_wireguard` to your nagios plugin folder and set executable.

* Add the following to your `nrpe.cfg` file
```
command[wireguard]=sudo /usr/lib/nagios/plugins/check_wireguard
```

* Set your nagios user to be able to run the plugin without a password
```
nagios    ALL=(ALL) NOPASSWD: /usr/lib/nagios/plugins/check_wireguard
```

## Examples

* Run with the `-h` argument to see all options
```
check_wireguard -h
```

* Specify the path to the `wg` binary. Default is `/usr/bin/wg`
```
check_wireguard -b /usr/local/wireguard/bin/wg
```

* Specify after how many seconds since the last handshake, a peer should be considered disconnected. Default is `300` seconds. If set to 0, a peer will be considered connected after a single handshake no matter how long ago it was
```
check_wireguard -s 600
```

## Future Work

* Compare config against current running config to determine interfaces that are offline

## Changelog

* 2021-11-15 :: 0.5.0   :: Update function seconds_since_handshake() to handle string 'Now'
* 2021-11-12 :: 0.4.0   :: Add extra output on error when failing to parse handshake value
* 2018-08-31 :: 0.3.0   :: Add -s switch for connection timeout calculation
* 2018-08-30 :: 0.2.0   :: Add -i switch for expected interfaces
* 2018-08-30 :: 0.1.0   :: First relase

## Site

https://gitlab.com/alasdairkeyes/nagios-plugin-check_wireguard

## Author

* Alasdair Keyes - https://akeyes.co.uk/

## License

Released under GPL V3 - See included license file.
