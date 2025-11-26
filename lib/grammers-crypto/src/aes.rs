// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use std::mem;
use std::convert::TryInto;

// Вспомогательная функция для быстрого XOR 16-байтных блоков
#[inline(always)]
fn xor_in_place(dst: &mut [u8; 16], src: &[u8; 16]) {
    // Безопасное преобразование в u128 для ускорения XOR
    // Компилятор превратит это в SIMD инструкции или работу с регистрами
    let d = u128::from_ne_bytes(*dst);
    let s = u128::from_ne_bytes(*src);
    *dst = (d ^ s).to_ne_bytes();
}

pub fn ige_encrypt(buffer: &mut [u8], key: &[u8; 32], iv: &[u8; 32]) {
    let len = buffer.len();
    assert!(len % 16 == 0);

    let key = GenericArray::from_slice(key);
    let cipher = aes::Aes256::new(key);

    let mut iv1: [u8; 16] = iv[..16].try_into().unwrap();
    let mut iv2: [u8; 16] = iv[16..].try_into().unwrap();

    // Используем chunks_exact_mut, чтобы убрать проверки границ внутри цикла
    for block in buffer.chunks_exact_mut(16) {
        let block_array: &mut [u8; 16] = block.try_into().unwrap();

        // Сохраняем оригинал (plaintext) для обновления iv2 в конце
        let plaintext_block = *block_array;

        // block = block XOR iv1
        xor_in_place(block_array, &iv1);

        // block = encrypt(block)
        let g_block = GenericArray::from_mut_slice(block_array);
        cipher.encrypt_block(g_block);

        // block = block XOR iv2
        xor_in_place(block_array, &iv2);

        // Обновляем IVs для следующего шага
        // iv1 становится текущим шифротекстом
        iv1 = *block_array;
        // iv2 становится предыдущим открытым текстом
        iv2 = plaintext_block;
    }
}

/// Decrypt the input ciphertext using the AES-IGE mode.
pub fn ige_decrypt(ciphertext: &[u8], key: &[u8; 32], iv: &[u8; 32]) -> Vec<u8> {
    let size = ciphertext.len();
    assert!(size % 16 == 0);
    let mut plaintext = vec![0; size];

    let key = GenericArray::from_slice(key);
    let cipher = aes::Aes256::new(key);
    let mut iv = *iv;
    let (iv1, iv2) = iv.split_at_mut(16);

    for (ciphertext_block, plaintext_block) in ciphertext.chunks(16).zip(plaintext.chunks_mut(16)) {
        // block = block XOR iv2
        plaintext_block
            .iter_mut()
            .zip(ciphertext_block)
            .zip(iv2.as_ref())
            .for_each(|((a, x), b)| *a = x ^ b);

        // block = decrypt(block);
        let plaintext_block = GenericArray::from_mut_slice(plaintext_block);
        cipher.decrypt_block(plaintext_block);

        // block = block XOR iv1
        plaintext_block
            .iter_mut()
            .zip(iv1.as_ref())
            .for_each(|(a, b)| *a ^= b);

        // save plaintext and adjust iv
        iv1.copy_from_slice(ciphertext_block);
        iv2.copy_from_slice(plaintext_block);
    }

    plaintext
}
