"""
Interactive Cryptanalysis Tool

Requirements: place this file alongside the following modules (provided earlier):
 - monoalphabetic_cryptanalysis.py  (attacks, fitness functions)
 - contextual_scorer.py             (ContextualScorer)
 - manual_key_editor.py             (ManualKeyEditor)

This script provides two interactive modes for manual refinement of substitution keys:
 1) REPL mode (default) -- simple text-based command loop
 2) TUI mode (`--tui`) -- lightweight curses-based interface (if your terminal supports it)

Usage:
  python interactive_cryptanalysis.py --ciphertext "ENCRYPTED TEXT" --mode repl
  python interactive_cryptanalysis.py --ciphertext "ENCRYPTED" --mode auto  # runs hillclimb then enters REPL
  python interactive_cryptanalysis.py --ciphertext "..." --mode auto --tui

Commands inside REPL:
  show                - show current key and mapped plaintext
  swap A B            - swap cipher letters A and B
  assign C P          - set mapping C -> P (cipher C maps to plain P)
  lock C / unlock C   - lock/unlock a cipher position
  rand                - randomize unlocked positions
  suggest [n]         - show top-n suggested swaps from scorer (default n=5)
  applyswap A B       - apply swap and show new score
  undo / redo
  save path.json      - save current mapping
  load path.json      - load mapping
  exit                - quit

TUI keys (when --tui enabled):
  q - quit
  s - suggest best swap
  r - randomize unlocked
  u - undo
  d - redo
  left/right/up/down - navigate mapping grid
  space - swap currently selected with highlighted

Note: this is a lightweight interface for human-in-the-loop cryptanalysis. It assumes
ciphertext is mainly uppercase A-Z and that the manual key editor and contextual scorer
modules are available as imports.
"""

import argparse
import sys
import os
import shlex

try:
    # attempt to import the supporting modules
    import monoalphabetic_cryptanalysis as mac
    from contextual_scorer import ContextualScorer
    from manual_key_editor import ManualKeyEditor
except Exception as e:
    # If imports fail, provide clear instructions and re-raise
    print("\nERROR importing required modules. Make sure the following files exist in the same folder:\")
    print("  - monoalphabetic_cryptanalysis.py")
    print("  - contextual_scorer.py")
    print("  - manual_key_editor.py")
    print("Import error:", e)
    raise


def run_hillclimb_initial(ciphertext, scorer, restarts=30, iters=2000):
    print("Running hillclimb (may take a while)...")
    key, plain, sc = mac.hillclimb_substitution_with_scorer(ciphertext, scorer, restarts=restarts, iters=iters)
    print(f"Hillclimb done. score={sc:.3f}")
    return key, plain, sc


def repl_loop(ciphertext, editor: ManualKeyEditor, scorer: ContextualScorer):
    print("Entering interactive REPL. Type 'help' for commands.")
    while True:
        try:
            line = input('crypt> ').strip()
        except (EOFError, KeyboardInterrupt):
            print('\nExiting.')
            break
        if not line:
            continue
        parts = shlex.split(line)
        cmd = parts[0].lower()
        args = parts[1:]
        if cmd in ('quit','exit'):
            break
        elif cmd == 'help':
            print(REPL_HELP)
        elif cmd == 'show':
            print('Key:', editor.key)
            print('Mapping:', editor.pretty_table())
            print('Plain candidate:')
            print(editor.apply(ciphertext))
            print('Score:', scorer.score(editor.apply(ciphertext)))
        elif cmd == 'swap' and len(args) == 2:
            try:
                editor.swap(args[0], args[1])
                print('Swapped', args[0], args[1])
            except Exception as e:
                print('Error:', e)
        elif cmd == 'assign' and len(args) == 2:
            try:
                editor.assign(args[0], args[1])
                print('Assigned', args[0], '->', args[1])
            except Exception as e:
                print('Error:', e)
        elif cmd == 'lock' and len(args) == 1:
            editor.lock(args[0])
            print('Locked', args[0])
        elif cmd == 'unlock' and len(args) == 1:
            editor.unlock(args[0])
            print('Unlocked', args[0])
        elif cmd == 'rand':
            editor.randomize_unlocked()
            print('Randomized unlocked positions')
        elif cmd == 'suggest':
            n = int(args[0]) if args else 5
            cands = editor.suggest_best_swap(scorer, ciphertext, top_k=n)
            if not cands:
                print('No improving swap found')
            else:
                for a,b,sc in cands:
                    print(f'{a} <-> {b} => score {sc:.3f}')
        elif cmd == 'applyswap' and len(args) == 2:
            try:
                sc = editor.apply_swap_and_score(args[0], args[1], scorer, ciphertext)
                print('Applied swap. New score:', sc)
            except Exception as e:
                print('Error:', e)
        elif cmd == 'undo':
            ok = editor.undo()
            print('Undo:', ok)
        elif cmd == 'redo':
            ok = editor.redo()
            print('Redo:', ok)
        elif cmd == 'save' and len(args) == 1:
            editor.save_to_file(args[0])
            print('Saved to', args[0])
        elif cmd == 'load' and len(args) == 1:
            editor.load_from_file(args[0])
            print('Loaded', args[0])
        else:
            print('Unknown command or wrong args. Type help.')


REPL_HELP = '''Available commands:
  show                - show current key and mapped plaintext
  swap A B            - swap cipher letters A and B
  assign C P          - set mapping C -> P (cipher C maps to plain P)
  lock C / unlock C   - lock/unlock a cipher position
  rand                - randomize unlocked positions
  suggest [n]         - show top-n suggested swaps from scorer (default n=5)
  applyswap A B       - apply swap and show new score
  undo / redo
  save path.json      - save current mapping
  load path.json      - load mapping
  help                - show this message
  exit                - quit
'''


# --------- Minimal curses-based TUI (optional) ---------
try:
    import curses
except Exception:
    curses = None


def run_curses_tui(stdscr, ciphertext, editor: ManualKeyEditor, scorer: ContextualScorer):
    curses.curs_set(0)
    h, w = stdscr.getmaxyx()
    selected = 0
    hint = ''
    while True:
        stdscr.clear()
        # header
        stdscr.addstr(0, 0, 'Interactive Cryptanalysis TUI (q to quit)')
        # mapping grid (2 rows of 13 each)
        key = editor.key
        for i in range(26):
            row = 2 + (i // 13) * 2
            col = (i % 13) * 4
            s = f"{ALPHABET[i]}->{key[i]}"
            if i == selected:
                stdscr.attron(curses.A_REVERSE)
            stdscr.addstr(row, col, s)
            if i == selected:
                stdscr.attroff(curses.A_REVERSE)
        # plaintext preview
        plain = editor.apply(ciphertext)
        stdscr.addstr(6, 0, 'Plain candidate:')
        preview_lines = [plain[i:i+ w -1] for i in range(0, min(len(plain), (h-10)*(w-1)), w-1)]
        for idx,pl in enumerate(preview_lines):
            stdscr.addstr(7+idx, 0, pl)
        stdscr.addstr(h-3, 0, f'Score: {scorer.score(plain):.3f} | hint: {hint}')
        stdscr.refresh()
        ch = stdscr.getch()
        hint = ''
        if ch == ord('q'):
            break
        elif ch in (curses.KEY_RIGHT, ord('l')):
            selected = (selected + 1) % 26
        elif ch in (curses.KEY_LEFT, ord('h')):
            selected = (selected - 1) % 26
        elif ch in (curses.KEY_DOWN, ord('j')):
            selected = (selected + 13) % 26
        elif ch in (curses.KEY_UP, ord('k')):
            selected = (selected - 13) % 26
        elif ch == ord('r'):
            editor.randomize_unlocked()
            hint = 'randomized unlocked'
        elif ch == ord('u'):
            editor.undo(); hint='undo'
        elif ch == ord('d'):
            editor.redo(); hint='redo'
        elif ch == ord('s'):
            cands = editor.suggest_best_swap(scorer, ciphertext, top_k=1)
            if cands:
                a,b,sc = cands[0]
                hint = f'suggests {a}<->{b} score {sc:.3f}'
            else:
                hint = 'no suggesting swap'
        elif ch == ord(' '):
            # swap selected with next (example behaviour) or with user input
            # for simplicity swap with selected+1
            other = (selected+1)%26
            a = ALPHABET[selected]; b = ALPHABET[other]
            try:
                editor.swap(a,b)
                hint = f'swapped {a}<->{b}'
            except Exception as e:
                hint = str(e)
        # else ignore


def main():
    parser = argparse.ArgumentParser(description='Interactive cryptanalysis tool (REPL or curses TUI)')
    parser.add_argument('--ciphertext', '-c', required=True, help='Ciphertext to analyze')
    parser.add_argument('--mode', choices=['repl','auto'], default='repl', help='repl: start with random key; auto: run hillclimb first')
    parser.add_argument('--tui', action='store_true', help='Use curses TUI (if available)')
    parser.add_argument('--restarts', type=int, default=30, help='Restarts for hillclimb when mode=auto')
    parser.add_argument('--iters', type=int, default=2000, help='Iterations per restart for hillclimb')
    args = parser.parse_args()

    ciphertext = args.ciphertext
    scorer = ContextualScorer()

    editor = ManualKeyEditor()
    if args.mode == 'auto':
        try:
            key, plain, sc = run_hillclimb_initial(ciphertext, scorer, restarts=args.restarts, iters=args.iters)
            if key:
                editor.reset(new_key=key)
                print('Initial key loaded from hillclimb.')
                print('Score:', sc)
        except Exception as e:
            print('Hillclimb failed or interrupted:', e)

    if args.tui:
        if curses is None:
            print('Curses not available on this platform. Falling back to REPL.')
            repl_loop(ciphertext, editor, scorer)
        else:
            curses.wrapper(run_curses_tui, ciphertext, editor, scorer)
    else:
        repl_loop(ciphertext, editor, scorer)

if __name__ == '__main__':
    main()
