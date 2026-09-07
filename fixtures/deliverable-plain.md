# widget

A small widget library for laying out resizable panels on a grid.

## Installation

    pip install widget

## Running the tests

From the repository root:

    python -m unittest discover -s tests

The suite is offline and finishes in under a second.

## Usage

    from widget import Grid

    grid = Grid(columns=12, gutter=8)
    grid.place("sidebar", span=3)
    grid.place("main", span=9)

## CHANGELOG

### 0.2.0

- Added the resize handle.
- Fixed an off by one in the grid snap.

### 0.1.0

- First release.
