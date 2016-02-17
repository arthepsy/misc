#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os, sys, json

SUBLIME_SESSION = '~/.config/sublime-text-3/Local/Session.sublime_session'
SUBLIME_PREFIX = 'sublime.session.'

def main():
    fn = os.path.expanduser(SUBLIME_SESSION) 
    with open(fn, 'r') as fp:
        c = fp.read()
    j = json.loads(c, strict=False)
    w = j['windows']
    bc = 0
    for i in range(len(w)):
        b = w[i]['buffers']
        for k in b:
            bc += 1
            if 'file' in k:
                print '#{:02d}: {}'.format(bc, k['file'])
            elif 'contents' in k:
                fn = '{}{:02d}.txt'.format(SUBLIME_PREFIX, bc)
                print '#{:02d}: \t // extracted as {}'.format(bc, fn)
                with open(fn, 'w') as fp:
                    fp.write(k['contents'])
            else:
                print '#{:02d}: unknown'.format(bc)

if __name__ == '__main__':
    main()

