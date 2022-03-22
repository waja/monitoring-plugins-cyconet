#!/usr/bin/env python3

from argparse import ArgumentParser, Namespace
import re
from typing import Any, List, Dict, Tuple, Optional
import shelve
import sys
from pathlib import Path

__PREV_DATA__ = '{}/.ethMonCache'.format(Path.home().as_posix())
__total__ = 'tot_{}'
__old__ = 'old_{}'

__scale__ = {
    'KB': lambda x: x / 1000,
    'Kb': lambda x: (x*8) / 1000,
    'MB': lambda x: x / 1000**2,
    'Mb': lambda x: (x*8) / 1000**2,
    'GB': lambda x: x / 1000**3,
    'Gb': lambda x: (x*8) / 1000**3
}

__to_bytes__ = {
    'KB': lambda x: x * 1000,
    'Kb': lambda x: (x * 1000) / 8,
    'MB': lambda x: x * 1000**2,
    'Mb': lambda x: (x * 1000**2) / 8,
    'GB': lambda x: x * 1000**3,
    'Gb': lambda x: (x * 1000**3) / 8
}


def options_parser() -> Namespace:
    _scalers = [i for i in __scale__.keys()]
    parser = ArgumentParser('ethMon')
    parser.add_argument('-i', '--interface', required=True, type=str, help='Network interface')
    parser.add_argument('-w', '--warning', type=str, required=True, help='Warning threshold')
    parser.add_argument('-c', '--critical', type=str, required=True, help='Critical threshold')
    parser.add_argument('-s', '--scale', choices=_scalers, help='Scaled results {}'.format(_scalers))
    parser.add_argument('--interval', type=int, help='Interval between the checks (in seconds)')

    return parser.parse_args()


def threshold_spec(threshold: str) -> bool:
    """
    Check for ranges specified in the warning/critical options
    """
    try:
        x, y = threshold.split(':')
        return True
    except ValueError:
        return False

def to_int(x: str) -> int:
    """
    Try to convert a value to integer. Always returns zero on unsuccessfull conversion

    :param x: Any 
    """
    try:
        return int(x)
    except:
        return 0

def threshold_extract(threshold: str) -> Tuple[int, int, bool]:
    """
    Extract the range and the inner/outer parameter
    

    :return: upper (int), lower (int), inner (bool)
    """
    lower, upper = threshold.split(':')
    if lower == '':
        lower = 0
    if upper == '':
        """ Set the upper limit to a very large number if not specified """
        upper = 10*10**256
    if lower.startswith('@'):
        lower = lower.lstrip('@')
        inner = True
    else:
        inner = False
    
    if to_int(lower) > to_int(upper):
        raise ValueError('Invalid value in threshold specification. lower > upper')
    return to_int(lower), to_int(upper), inner


def get_old_data(iface: str) -> Tuple[int, int, int, int]:
    """
    Get the old interface data from the storage (if available)

    :param iface: The name of the interface
    :return: RX bytes, TX bytes, RX Total, TX Total values from the previous run
    """
    storage = shelve.open(__PREV_DATA__)
    rx, tx = storage.get(__old__.format(iface), (0, 0))
    rx_total, tx_total = storage.get(__total__.format(iface), (0, 0))
    storage.close()
    return rx, tx, rx_total, tx_total


def update_stats(iface: str, rx_bytes: int, tx_bytes: int) -> None:
    """
    Store the data from the current run

    :param iface: The name of the interface
    :param rx_bytes: RX bytes as read from the net/dev file
    :param tx_bytes: TX bytes values as read from the net/dev file
    :return:
    """
    storage = shelve.open(__PREV_DATA__)
    rx_total, tx_total = storage.get(__total__.format(iface), (0, 0))
    storage[__total__.format(iface)] = (rx_total + rx_bytes, tx_total + tx_bytes)
    storage[__old__.format(iface)] = (rx_bytes, tx_bytes)
    storage.close()
    return


def get_iface_stats(iface: str) -> Tuple[int, int]:
    """
    Extract the interface statistics

    :param iface:
    :return:
    """
    """
    RX/TX slots
    bytes packets errs drop fifo frame compressed multicast
    """
    _rx_bytes = 0
    _tx_bytes = 0
    slots = []
    with open('/proc/net/dev', 'r') as stat:
        for line in stat:
            if iface not in line:
                continue
            line = line.rstrip()
            line = re.sub(r'\s\s+', ' ', line)
            line = line.lstrip(' ')
            slots = line.split(' ')
    if len(slots) > 10:
        _rx_bytes = int(slots[1])
        _tx_bytes = int(slots[9])
    return _rx_bytes, _tx_bytes


def speed_calc(old_data: tuple, current_data: tuple) -> Tuple[int, int]:
    """
    Calculate the changes between the old and new data

    :param data:
    :param current_data:
    :return:
    """
    old_rx, old_tx = old_data[:2]
    cur_rx, cur_tx = current_data

    return cur_rx - old_rx, cur_tx - old_tx


def speed_scaler(val: int, scaler: str) -> str:
    """
    available ['KB', 'Kb', 'MB', 'Mb', 'GB', 'Gb']
    """
    if scaler not in __scale__.keys():
        raise
    return str(round(__scale__[scaler](val), 3))


def speed_normalizer(val: int, scaler: str) -> int:
    """
    available ['KB', 'Kb', 'MB', 'Mb', 'GB', 'Gb']
    """
    if scaler not in __to_bytes__.keys():
        raise
    return int(__to_bytes__[scaler](val))


def final_string(rx_s: int, tx_s: int, warning_s: int, crit_s: int, code: int):
    status = 'OK'
    if code == 2:
        status = 'CRITICAL'
    elif code == 1:
        status = 'WARNING'

    return '{} bandwidth utilization | rx={}B;{}B;{}B tx={}B;{}B;{}B'.format(
        status, rx_s, warning_s, crit_s, tx_s, warning_s, crit_s
    )


if __name__ == '__main__':
    options = options_parser()
    old = get_old_data(options.interface)
    exit_c = 0
    if threshold_spec(options.warning) or threshold_spec(options.critical):
        use_thresholds = True
        try:
            warn_lower, warn_upper, warn_inner = threshold_extract(options.warning)
            crit_lower, crit_upper, crit_inner = threshold_extract(options.critical)
        except ValueError:
            print('Invalid range specification.')
            sys.exit(100)
    else:
        use_thresholds = False

    current = get_iface_stats(options.interface)
    rx_speed, tx_speed = speed_calc(old, current)

    if options.interval:
        interval_scaler = lambda x: int(x / options.interval)
        rx_speed = interval_scaler(rx_speed)
        tx_speed = interval_scaler(tx_speed)

    update_stats(options.interface, *current)

    if options.scale:
        _suffix = ' {}'.format(options.scale)
        c_0 = speed_scaler(current[0], options.scale) + _suffix
        c_1 = speed_scaler(current[1], options.scale) + _suffix
        rx_s = speed_scaler(rx_speed, options.scale) + _suffix
        tx_s = speed_scaler(tx_speed, options.scale) + _suffix

        if use_thresholds is False:
            warning_s = speed_normalizer(to_int(options.warning), options.scale)
            if warning_s < rx_speed or warning_s < tx_speed:
                exit_c = 1
            critical_s = speed_normalizer(to_int(options.critical), options.scale)
            if critical_s < rx_speed or critical_s < tx_speed:
                exit_c = 2
        else:
            warn_s_low = speed_normalizer(warn_lower, options.scale)
            warn_s_up = speed_normalizer(warn_upper, options.scale)
            crit_s_low = speed_normalizer(crit_lower, options.scale)
            crit_s_up = speed_normalizer(crit_upper, options.scale)

            if warn_inner is True:
                if (warn_s_low <= rx_speed <= warn_s_up) or (warn_s_low <= tx_speed <= warn_s_up):
                    exit_c = 1
            else:
                if (warn_s_low >= rx_speed or warn_s_up <= rx_speed) or (warn_s_low >= tx_speed or warn_s_up <= tx_speed):
                    exit_c = 1
            if crit_inner is True:
                if (crit_s_low <= rx_speed <= crit_s_up) or (crit_s_low <= tx_speed <= crit_s_up):
                    exit_c = 2
            else:
                if (crit_s_low >= rx_speed or crit_s_up <= rx_speed) or (crit_s_low >= tx_speed or crit_s_up <= tx_speed):
                    exit_c = 2
            warning_s = warn_s_low
            critical_s = crit_s_low
                

        print('RX {}: {}, TX {}: {}; RX speed: {} TX speed: {}'.format(
            options.scale, c_0, options.scale, c_1, rx_s, tx_s
        ), end='; ')
        print(final_string(rx_speed, tx_speed, warning_s, critical_s, exit_c))

    else:
        print('RX bytes: {}, TX bytes: {}; RX speed: {}, TX speed {}'.format(
            current[0], rx_speed, current[1], tx_speed
        ), end='; ')
        if use_thresholds is False:
            warning_s = to_int(options.warning)
            if warning_s < rx_speed or warning_s < tx_speed:
                exit_c = 1
            critical_s = to_int(options.critical)
            if critical_s < rx_speed or critical_s <= tx_speed:
                exit_c = 2
        else:
            if crit_inner is True:
                if (warn_lower <= rx_speed <= warn_upper) or (warn_lower <= tx_speed <= warn_upper):
                    exit_c = 1
            else:
                if (warn_lower >= rx_speed or warn_upper <= rx_speed) or (warn_lower >= tx_speed or warn_upper <= rx_speed):
                    exit_c = 1
            if crit_inner is True:
                if (crit_lower <= rx_speed <= crit_upper) or (crit_lower <= tx_speed <= crit_upper):
                    exit_c = 2
            else:
                if (crit_lower >= rx_speed or crit_upper <= rx_speed) or (crit_lower >= tx_speed or crit_upper <= tx_speed):
                    exit_c = 2
            warning_s = warn_lower
            critical_s = crit_lower

        print(final_string(rx_speed, tx_speed, warning_s, critical_s, exit_c))

    sys.exit(exit_c)
