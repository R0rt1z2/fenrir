#!/usr/bin/env python3

import argparse
import sys

from devices import DEVICES


def main() -> int:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description='Multi-stage bootloader injector'
    )
    parser.add_argument('device', help='Device name')
    parser.add_argument('image', help='Bootloader image path', nargs='?')
    parser.add_argument(
        '-o', '--output', help='Output file path', default='lk.patched'
    )
    parser.add_argument('--config', '-c', help='JSON configuration file')
    parser.add_argument(
        '--payload-dir',
        '-p',
        default='payload/build',
        help='Payload directory (default: payload/build)',
    )
    parser.add_argument(
        '--list-stages',
        action='store_true',
        help='List available stages and exit',
    )

    args: argparse.Namespace = parser.parse_args()

    if args.list_stages and not args.image:
        for dev in DEVICES:
            if dev.name.lower() == args.device.lower():
                return list_stages_for_device(dev, args)
    
    if not args.image:
        usage()
        print("\nERROR: Bootloader image is required unless --list-stages is specified")
        return 1

    for dev in DEVICES:
        if dev.name.lower() == args.device.lower():
            return dev.execute(args)

    usage()
    print('')
    raise RuntimeError(
        'Could not locate %s in supported devices list. Available devices: %s' % 
        (args.device, ', '.join([dev.name for dev in DEVICES]))
    )


def list_stages_for_device(device, args):
    print("Available stages for %s (%s):" % (device.name, device.codename))
    for stage_name, stage in device.stages.items():
        base_addr, pivot_addr = stage.get_addresses()
        status = "enabled" if stage.is_enabled() else "disabled"
        description = stage.get_description()
        desc_text = " - %s" % description if description else ""
        print("  %s: base=0x%X, pivot=0x%X (%s)%s" % (stage_name, base_addr, pivot_addr, status, desc_text))
    return 0


def usage() -> None:
    print('Usage: ./inject.py <device> [image] [options]')
    print('')
    print('List of supported devices:')
    for dev in DEVICES:
        print(
            '- %s (%s): %s'
            % (dev.name, dev.codename, ', '.join(sorted(dev.stages.keys())))
        )
    print('\nTo list stages: ./inject.py <device> --list-stages')
    print('To patch a bootloader: ./inject.py <device> <image> [options]')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        usage()
    else:
        exit(main())