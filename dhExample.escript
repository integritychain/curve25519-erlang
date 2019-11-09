#!/usr/bin/escript

main(_) ->

  %% Run 1M testcase
  io:format("Testing...~n"),
  io:format("Expecting 7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424~n"),
  curve25519:test_k_u_iter(
      16#0900000000000000000000000000000000000000000000000000000000000000,
      16#0900000000000000000000000000000000000000000000000000000000000000,
      1000000),

  %% Force strong randomness, generate public IV and declare common point G
  _ = crypto:rand_seed(),
  G = 9,

  %% Alice and Bob generate private keys, never shared directly
  Alice_private_key = rand:uniform(16#7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
  Bob_private_key = rand:uniform(16#7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),


  %% Alice and Bob generate public keys to share with each other (and Eve)
  Alice_public_key = curve25519:mul_k_u(Alice_private_key, G),
  Bob_public_key = curve25519:mul_k_u(Bob_private_key, G),

  %% Alice and Bob use their private key and shared key to derive shared secret
  Alice_shared_key = curve25519:mul_k_u(Alice_private_key, Bob_public_key),
  Bob_shared_key = curve25519:mul_k_u(Bob_private_key, Alice_public_key),

  %% Alice encrypts a secret message with their shared key and sends it to Bob
  IV = crypto:strong_rand_bytes(16),

  CipherText = crypto:block_encrypt(aes_cbc, IV,
      <<Alice_shared_key:128/little-unsigned-integer-unit:1>>, <<"A secret message">>),

  %% Bob decryptes the secret message with their shared key and prints to terminal
  PlainText = crypto:block_decrypt(aes_cbc, IV,
      <<Bob_shared_key:128/little-unsigned-integer-unit:1>>, CipherText),
  io:format("~s~n", [PlainText]).
