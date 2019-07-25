/*
  Copyright (C) 2018-2019 The Purple Core Developers.
  This file is part of the Purple Core Library.

  The Purple Core Library is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The Purple Core Library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the Purple Core Library. If not, see <http://www.gnu.org/licenses/>.
*/

use std::fmt;

#[derive(Debug, Clone)]
pub struct Stack<T>(Vec<T>);

impl<T: fmt::Debug + Clone> Stack<T> {
    pub fn new() -> Stack<T> {
        Stack(vec![])
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn push(&mut self, value: T) {
        self.0.push(value);
    }

    pub fn pick(&mut self, idx: usize) {
        let len = self.0.len();
        if idx >= len {
            panic!("There is no item at the given index!")
        }

        let item = self.0[idx].clone();

        self.0.push(item);
    }

    pub fn pop(&mut self) -> T {
        self.0.pop().expect("Unable to pop from empty stack!")
    }

    pub fn peek(&self) -> &T {
        let len = self.0.len();
        if len == 0 {
            panic!("Cannot peek into empty stack!")
        }
        &self.0[len - 1]
    }

    pub fn peek_mut(&mut self) -> &mut T {
        let len = self.0.len();
        if len == 0 {
            panic!("Cannot peek into empty stack!")
        }
        &mut self.0[len - 1]
    }

    pub fn as_slice(&self) -> &[T] {
        self.0.as_slice()
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        self.0.as_mut_slice()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new() {
        let stack: Stack<usize> = Stack::new();
        assert!(stack.is_empty());
    }

    #[test]
    fn push() {
        let mut stack: Stack<usize> = Stack::new();
        stack.push(13);
        assert!(!stack.is_empty());
    }

    #[test]
    fn pick() {
        let mut stack: Stack<usize> = Stack::new();
        stack.push(1);
        stack.push(2);
        stack.push(3);

        assert_eq!(*stack.peek(), 3);

        stack.pick(0);

        assert_eq!(*stack.peek(), 1);
    }

    #[test]
    fn pop() {
        let mut stack: Stack<usize> = Stack::new();
        stack.push(12);
        stack.push(13);
        let value = stack.pop();
        assert_eq!(value, 13);
    }

    #[test]
    #[should_panic(expected = "empty stack")]
    fn empty_pop() {
        let mut stack: Stack<usize> = Stack::new();
        stack.pop();
    }

    #[test]
    fn peek() {
        let mut stack: Stack<usize> = Stack::new();
        stack.push(13);
        assert_eq!(*stack.peek(), 13)
    }

    #[test]
    #[should_panic(expected = "empty stack")]
    fn empty_peek() {
        let stack: Stack<usize> = Stack::new();
        stack.peek();
    }

    #[test]
    #[should_panic(expected = "no item at the given index")]
    fn empty_pick() {
        let mut stack: Stack<usize> = Stack::new();
        stack.pick(0);
    }
}
