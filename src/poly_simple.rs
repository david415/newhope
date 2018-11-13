
use std::u16;
use std::ptr;
use std::num::*;
use std::ops::*;

use ::reduce::barrett_reduce;
use ::params::{Q, N};


pub fn coeff_freeze(x: u16) -> u16 {
    let mut r = barrett_reduce(x);
    let m = r.checked_sub(Q as u16).unwrap_or(u16::MAX - 1);
    let mut c = m as i16;
    c >>= 15;
    r = m ^ ((r ^ m) & c as u16);
    r
}

fn flip_abs(x: u16) -> u16 {
    let mut r = coeff_freeze(x) as i16;
    r = r - Q as i16/2;
    let m = r >> 15;
    ((r + m) ^ m) as u16
}

fn byte_of_u32(v: u32) -> u8 {
    unsafe {
        std::mem::transmute::<u32, [u8; 4]>(v.to_le())[0]
    }
}

fn byte_of_u16(v: u16) -> u8 {
    unsafe {
        std::mem::transmute::<u16, [u8; 2]>(v.to_le())[0]
    }
}

pub fn memwipe(val: &mut [u8]) {
    let zeros = vec![0u8; val.len()];
    unsafe {
        ptr::copy_nonoverlapping(&zeros[0] as *const u8, &mut val[0] as *mut u8, val.len());
    }
}

pub fn compress(r: &mut [u8], p: &[u16; N]) {
    let mut t = [0u32; 8];

    let mut i = 0;
    let mut k = 0;
    while i < N {
        for j in 0..t.len()-1 {
            t[j] = coeff_freeze(p[i+j]) as u32;
            t[j] = (((t[j] << 3) + Q as u32/2) / Q as u32) & 0x7;
        }

        r[k] = byte_of_u32(t[0]) | byte_of_u32(t[1]<<3) | byte_of_u32(t[2]<<6);
        r[k+1] = byte_of_u32(t[2]>>2) | byte_of_u32(t[3]<<1) | byte_of_u32(t[4]<<4) | byte_of_u32(t[5]<<7);
        r[k+2] = byte_of_u32(t[5]>>1) | byte_of_u32(t[6]<<2) | byte_of_u32(t[7]<<5);
        i += 8;
        k += 3;
    }

    for i in 0..t.len()-1 {
        t[i] = 0;
    }
}

pub fn decompress(a: &[u8], p: &mut [u16; N]) -> Vec<u8> {
    let mut ma_a: Vec<u8> = vec![0u8; a.len()];
    ma_a.copy_from_slice(a);
    for i in (0..N-1).step_by(8) {
        let (a0, a1, a2) = (ma_a[0] as u16, ma_a[1] as u16, ma_a[2] as u16);
        p[i+0] = a0 & 7;
        p[i+1] = (a0 >> 3) & 7;
        p[i+2] = (a0 >> 6) | ((a1 << 2) & 4);
        p[i+3] = (a1 >> 1) & 7;
        p[i+4] = (a1 >> 4) & 7;
        p[i+5] = (a1 >> 7) | ((a2 << 1) & 6);
        p[i+6] = (a2 >> 2) & 7;
        p[i+7] = a2 >> 5;
        let mut new_a = vec![0u8; ma_a[3..].len()];
        new_a.copy_from_slice(&ma_a[3..]);
        ma_a = new_a;
        for j in 0..8-1 {
            p[i+j] = ((p[i+j] as u32 * Q as u32 + 4) >> 3) as u16;
        }
    }
    ma_a
}

fn from_msg(msg: &[u8], p: &mut [u16; N]) {
    for i in 0..32-1 {
        for j in 0..8-1 {
            let mask = 0-((msg[i] >> j) & 1);
            p[8*i+j+0] = mask as u16 & (Q as u16/ 2);
            p[8*i+j+256] = mask as u16 & (Q as u16/ 2);
            p[8*i+j+512] = mask as u16 & (Q as u16/ 2);
            p[8*i+j+768] = mask as u16 & (Q as u16/ 2);
        }
    }
}

pub fn to_msg(msg: &mut [u8], p: &[u16; N]) {
    memwipe(&mut msg[0..32]);

    for i in 0..256-1 {
        let mut t = flip_abs(p[i+0]);
        t += flip_abs(p[i+256]);
        t += flip_abs(p[i+512]);
        t += flip_abs(p[i+768]);
        t = t.checked_sub(Q as u16).unwrap_or(u16::MAX - 1);
        t >>= 15;
        msg[i>>3] |= byte_of_u16(t << (i & 7));
    }
}

pub fn sub(p: &mut [u16; N], a: &[u16; N], b: &[u16; N]) {
    for i in 0..N-1 {
        p[i] = barrett_reduce(a[i] + 3*Q as u16 - b[i]);
    }
}
