---
title: picoCTF 2024 Writeup 
date: 2024-08-20
categories: [picoCTF]
tags: [pentest, picoCTF, ctf]
---

Writeups for the picoCTF 2024.

<hr />

Let's start with the challenges.

## General Skills

### Binary Search

We need to find the flag, There are 1000 possibilities but only 10 tries.

<figure><img src="/assets/picoCTF/General-Skills/binary-search.png" alt="Solution for Binary Search"></figure>

Everytime we enter a number it gives us a prompt wether the answer is higher or lower. We can divide the remainder in half to get to the desired number most efficiently.

Flag:
```
picoCTF{g00d_gu355_bee04a2a}
```

### Time Machine

<figure><img src="/assets/picoCTF/General-Skills/time-machine.png" alt="Solution for Time Machine"></figure>

We were given a folder with a `.git` folder which has logs which basically serves the purpose of a time machine.

Flag:
```
picoCTF{t1m3m@ch1n3_d3161c0f}
```

## Forensics

## Web Exploitation

## Cryptography

## Reverse Engineering

## Binary Exploitation