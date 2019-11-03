-module(curve25519).
-author("Eric Schorn").

-export([mul_k_u/2, test_k_u_iter/3]).

-define(PRIME,  16#7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED).
-define(K_AND,  16#7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF8).
-define(K_OR,   16#4000000000000000000000000000000000000000000000000000000000000000).
-define(U_AND,  16#7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF).
-define(ALL256, 16#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF).
-define(A24, 121665).


-spec(add(X :: non_neg_integer(), Y :: non_neg_integer()) -> non_neg_integer()).
add(X, Y) ->
  (X + Y) rem ?PRIME.


-spec(sub(X :: non_neg_integer(), Y :: non_neg_integer()) -> non_neg_integer()).
sub(X, Y) ->   %% Y - Y = 0 = PRIME   so   -Y = PRIME - Y
  (X + ?PRIME - Y) rem ?PRIME.


-spec(mul(X :: non_neg_integer(), Y :: non_neg_integer()) -> non_neg_integer()).
mul(X, Y) ->
  (X * Y) rem ?PRIME.


-spec(inv(X :: non_neg_integer()) -> non_neg_integer()).
inv(X) ->
  inv(X, ?PRIME - 2, 1).


-spec(inv(X :: non_neg_integer(), Exp :: non_neg_integer(), Result :: non_neg_integer())
      -> non_neg_integer()).
inv(_X, 0, Result) ->
  Result;

inv(X, Exp, Result) ->
  if
    Exp band 1  == 1->
      R1 = mul(Result, X);
    true ->
      R1 = Result
  end,
  X1 = mul(X, X),
  inv(X1, Exp bsr 1, R1).


-spec(mul_k_u(K :: non_neg_integer(), U :: non_neg_integer()) -> non_neg_integer()).
mul_k_u(K, U) ->  %% x_1 = u, x_2 = 1, z_2 = 0, x_3 = u, z_3 = 1, swap = 0
  K1 = binary:decode_unsigned(<<K:256/little-unsigned-integer-unit:1>>),
  K2 = (K1 band ?K_AND) bor ?K_OR,
  U1 = binary:decode_unsigned(<<U:256/little-unsigned-integer-unit:1>>),
  U2 = U1 band ?U_AND,
  mul_k_u(254, K2, U2, 1, 0, U2, 1, 0).


-spec(mul_k_u(T :: -1..254, _K :: non_neg_integer(), _X_1 :: non_neg_integer(), X_2 ::
      non_neg_integer(), Z_2 :: non_neg_integer(), X_3 ::non_neg_integer(), Z_3 ::
      non_neg_integer(), Swap :: 0..1) -> non_neg_integer()).
mul_k_u(T, _K, _X_1, X_2, Z_2, X_3, Z_3, Swap) when T == -1 ->
  {X_2a, _X_3a} = cswap(Swap, X_2, X_3),         %% (x_2, x_3) = cswap(swap, x_2, x_3)
  {Z_2a, _Z_3a} = cswap(Swap, Z_2, Z_3),         %% (z_2, z_3) = cswap(swap, z_2, z_3)
  Inverse = inv(Z_2a),                           %% Return x_2 * (z_2^(p - 2))
  Result = mul(X_2a, Inverse),
  binary:decode_unsigned(<<Result:256/little-unsigned-integer-unit:1>>);

mul_k_u(T, K, X_1, X_2, Z_2, X_3, Z_3, Swap) ->  %% For t = bits-1 down to 0:
  K_t = (K bsr T) band 1,                        %%   k_t = (k >> t) & 1
  Swap_a = Swap bxor K_t,                        %%   swap ^= k_t
  {X_2a, X_3a} = cswap(Swap_a, X_2, X_3),        %%   (x_2, x_3) = cswap(swap, x_2, x_3)
  {Z_2a, Z_3a} = cswap(Swap_a, Z_2, Z_3),        %%   (z_2, z_3) = cswap(swap, z_2, z_3)
  Swap_b = K_t,                                  %%   swap = k_t
  A = add(X_2a, Z_2a),                           %%   A = x_2 + z_2
  AA = mul(A, A),                                %%   AA = A^2
  B = sub(X_2a, Z_2a),                           %%   B = x_2 - z_2
  BB = mul(B, B),                                %%   BB = B^2
  E = sub(AA, BB),                               %%   E = AA - BB
  C = add(X_3a, Z_3a),                           %%   C = x_3 + z_3
  D = sub(X_3a, Z_3a),                           %%   D = x_3 - z_3
  DA = mul(D, A),                                %%   DA = D * A
  CB = mul(C, B),                                %%   CB = C * B
  XX1 = add(DA, CB),                             %%   x_3 = (DA + CB)^2
  X_3b = mul(XX1, XX1),
  XX2 = sub(DA, CB),                             %%   z_3 = x_1 * (DA - CB)^2
  XX3 = mul(XX2, XX2),
  Z_3b = mul(X_1, XX3),
  X_2b = mul(AA,BB),                             %%   x_2 = AA * BB
  XX4 = mul(?A24, E),                            %%   z_2 = E * (AA + a24 * E)
  XX5 = add(AA, XX4),
  Z_2b = mul(E, XX5),
  mul_k_u(T - 1, K, X_1, X_2b, Z_2b, X_3b, Z_3b, Swap_b).


-spec(cswap(Swap :: 0..1, X2 :: non_neg_integer(), X3 :: non_neg_integer()) ->
  {non_neg_integer(), non_neg_integer()}).
cswap(Swap, X2, X3) ->
  Dummy = Swap*?ALL256 band (X2 bxor X3),
  X2a = X2 bxor Dummy,
  X3a = X3 bxor Dummy,
  {X2a, X3a}.


-spec(test_k_u_iter(K :: non_neg_integer(), U :: non_neg_integer(), Iter ::
      non_neg_integer()) -> ok).
test_k_u_iter(K, U, Iter) when Iter > 0 ->
  %% For each iteration, set k to be the result of calling the function and
  %% u to be the old value of k.  The final result is the value left in k.
  K1 = mul_k_u(K, U),
  U1 = K,
  test_k_u_iter(K1, U1, Iter - 1);

test_k_u_iter(K, _U, 0) ->
  io:fwrite("Result is ~.16B~n", [K]).
%% curve25519:test_k_u_iter(
%%          16#0900000000000000000000000000000000000000000000000000000000000000,
%%          16#0900000000000000000000000000000000000000000000000000000000000000, 1000).
%% After 1K iterations:  684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51
%% After 1M iterations:  7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424