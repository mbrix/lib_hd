% Copyright (c) 2015 <Matthew Branton>
% See LICENSE
%
% BIP-32 HD deterministic key generation

-module(lib_hd).
-author('mbranton@emberfinancial.com').


-include_lib("../include/bip32.hrl").

-export([new/1,
		 new/2,
		 readable/1,
		 priv/1, 
		 pub/1,
		 private/1,
		 public/1,
		 derive/3,
		 serialize/1,
		 bip32_path/3]).

new(<<"xprv", _/binary>> = Base64Xpriv) ->
	<<16#0488ADE4:32, Depth:8, Fprint:32/bitstring, Cnum:32,
	  Chain:256/bitstring, 0:8, Key:256/bitstring, _Csum:32/bitstring>> = base58:base58_to_binary(binary_to_list(Base64Xpriv)),
	{bip32_priv_key, Key, Chain, Depth, Cnum, Fprint, mainnet};

new(<<"xpub", _/binary>> = Base64Xpub) ->
	<<16#0488B21E:32, Depth:8, Fprint:32/bitstring, Cnum:32,
	  Chain:256/bitstring, Key:264/bitstring, _Csum:32/bitstring>> = base58:base58_to_binary(binary_to_list(Base64Xpub)),
	{bip32_pub_key, Key, Chain, Depth, Cnum, Fprint, mainnet};

new(<<Seed:128/bitstring>>) -> new(seed, Seed);
new(<<Seed:256/bitstring>>) -> new(seed, Seed);
new(<<Seed:512/bitstring>>) -> new(seed, Seed);
new(_) -> error.

new(mnemonic, <<Mnemonic:512/bitstring>>) -> new(binary, private, Mnemonic);

new(seed, Seed) ->
	new(binary, private, hmac:hmac512(<<"Bitcoin seed">>, Seed)).

new(binary, private, <<PrivateKey:256/bitstring, ChainCode:256/bitstring>>) ->
	#bip32_priv_key{key = PrivateKey,
					chain_code = ChainCode,
					depth = 0,
					child_num = 0,
					finger_print = <<0:32>>,
				    network = mainnet};

new(binary, public, <<PubKey:256/bitstring, ChainCode:256/bitstring>>) ->
	#bip32_pub_key{key = PubKey,
				   chain_code = ChainCode,
				   depth = 0,
				   child_num = 0,
				   finger_print = <<0:32>>,
				   network = mainnet}.



base58_check(Bin) ->
	<<C:32/bitstring,_/binary>> = crypto:hash(sha256,
			crypto:hash(sha256, Bin)), 
	base58:binary_to_base58(iolist_to_binary([Bin, C])).

readable(Key) ->
	base58_check(serialize(Key)).

fingerprint(#bip32_priv_key{key = Key}) ->
	{ok, Pubkey} = libsecp256k1:ec_pubkey_create(Key, compressed),
	fingerprint(Pubkey);

fingerprint(#bip32_pub_key{key = Key}) ->
	fingerprint(Key);

fingerprint(Pubkey) ->
	<<Fingerprint:32/bitstring, _Rest/binary>> =
		crypto:hash(ripemd160, crypto:hash(sha256, Pubkey)),
	Fingerprint.

serialize(K) when is_record(K, bip32_priv_key) ->
	{bip32_priv_key, Key, Chain, Depth, Cnum, Fprint, _Network} = K,
	<<16#0488ADE4:32, Depth:8, Fprint/bitstring, Cnum:32,
	  Chain/bitstring, 0:8, Key/bitstring>>;

serialize(K) when is_record(K, bip32_pub_key) ->
	{bip32_pub_key, Key, Chain, Depth, Cnum, Fprint, _Network} = K,
	<<16#0488B21E:32, Depth:8, Fprint/bitstring, Cnum:32,
	  Chain/bitstring, Key/bitstring>>.

priv(K) when is_record(K, bip32_priv_key) -> K;
priv(K) when is_record(K, bip32_pub_key) -> error.

pub(K) when is_record(K, bip32_priv_key) ->
	{bip32_priv_key, Key, Chain, Depth, Cnum, Fprint, Network} = K,
	{ok, Pubkey} = libsecp256k1:ec_pubkey_create(Key, compressed),
	{bip32_pub_key, Pubkey, Chain, Depth, Cnum, Fprint, Network};

pub(K) when is_record(K, bip32_pub_key) -> K.

public(#bip32_priv_key{key = Key}) ->
	{ok, Pubkey} = libsecp256k1:ec_pubkey_create(Key, compressed),
	Pubkey;
public(#bip32_pub_key{key = Key}) -> Key.

private(#bip32_priv_key{key = Key}) -> Key;
private(#bip32_pub_key{}) -> error.

derive(path, Key, <<"m/", Path/binary>>) ->
	derive_pathlist(Key, 
					lists:map(fun(E) ->
									  case bin_reverse(E) of
									  	  <<"'", Hardened/binary>> ->
									  	  	  bin_to_num(bin_reverse(Hardened)) + 2147483648 ;
									  	  _ -> bin_to_num(E)
									  end end, binary:split(Path, <<"/">>, [global]))).

derive_pathlist(Key, []) -> Key;
derive_pathlist(Key, PathList) ->
	[Element|Rest] = PathList,
	derive_pathlist(derive_key(Key, Element), Rest).

derive_key(#bip32_priv_key{key = PrivKey, chain_code = C, depth = D} = K, I) when I > -1, I < 2147483648 -> %% Normal derivation 
	{ok, Pubkey} = libsecp256k1:ec_pubkey_create(PrivKey, compressed),
	K2 = new(binary, private, hmac:hmac512(C, <<Pubkey/bitstring, I:32>>)),
	{ok, NewKey} = libsecp256k1:ec_privkey_tweak_add(PrivKey, K2#bip32_priv_key.key),
	K2#bip32_priv_key{key = NewKey,
	                  depth = D+1,
					  finger_print = fingerprint(K),
					  child_num = I};

derive_key(#bip32_priv_key{key = PrivKey, chain_code = C, depth = D} = K, I) when I > 2147483647 ->  %% Hardened derivation	
	K2 = new(binary, private, hmac:hmac512(C, <<0:8, PrivKey/bitstring, I:32>>)),
	{ok, NewKey} = libsecp256k1:ec_privkey_tweak_add(PrivKey, K2#bip32_priv_key.key),
	K2#bip32_priv_key{key = NewKey,
	                  depth = D+1,
					  finger_print = fingerprint(K),
					  child_num = I};


derive_key(#bip32_pub_key{key = PubKey, chain_code = C, depth = D} = K, I) when I > -1, I < 2147483648 -> %% Normal derivation 
	K2 = new(binary, public, hmac:hmac512(C, <<PubKey/bitstring, I:32>>)),
	{ok, NewKey} = libsecp256k1:ec_pubkey_tweak_add(PubKey, K2#bip32_pub_key.key),
	K2#bip32_pub_key{key = NewKey,
					 depth = D+1,
					 finger_print = fingerprint(K),
					 child_num = I};

derive_key(K, I) when is_record(K, bip32_pub_key), I > 2147483647 ->  %% Hardened derivation	
	throw(public_key_derivation_error).



bip32_path(Change, AccountNum, AddressIndex) ->
	erlang:iolist_to_binary([<<"m/44'/0'/">>,
							 erlang:integer_to_binary(AccountNum),
							 <<"'/">>,
							 erlang:integer_to_binary(Change),
							 <<"/">>,
							 erlang:integer_to_binary(AddressIndex)]).



bin_to_num(Bin) ->
    N = binary_to_list(Bin),
    case string:to_float(N) of
        {error,no_float} -> list_to_integer(N);
        {_F,_Rest} -> error
    end.

bin_reverse(B) ->
   S = size(B)*8,
   <<X:S/integer-little>>=B,
   <<X:S/integer-big>>.
