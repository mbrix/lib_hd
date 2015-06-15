% Copyright (c) 2015 <Matthew Branton>
% See LICENSE
%
% BIP-32 HD test vectors

-module(lib_hd_tests).
-author('mbranton@emberfinancial.com').


-include_lib("../include/bip32.hrl").
-include_lib("eunit/include/eunit.hrl").

start() ->
	ok.

stop(_) ->
	ok.

create() ->
	A = lib_hd:new(<<"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi">>),
	?assertNotEqual(error, A),
	B = lib_hd:new(<<"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8">>),
	?assertNotEqual(error, B).


hmac512() ->
	%% RFC 4231
	Key = hexstr_to_bin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
	Data = hexstr_to_bin("4869205468657265"),
	Res = hexstr_to_bin("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"),
	?assertEqual(64, size(Res)),
	Result = hmac:hmac512(Key, Data),
	?assertEqual(Res, Result).

bip32_vectors1() ->
	Master = hexstr_to_bin("000102030405060708090a0b0c0d0e0f"),
	M = lib_hd:new(Master),
	%% Chain m
	?assertEqual("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
				 lib_hd:readable(lib_hd:pub(M))),
	?assertEqual("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
				 lib_hd:readable(M)),

	%% Chain m/0h
	?assertEqual("xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
				 lib_hd:readable(lib_hd:pub(lib_hd:derive(path, M, <<"m/0'">>)))),
	?assertEqual("xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
				 lib_hd:readable(lib_hd:derive(path, M, <<"m/0'">>))),

	%% chain m/0h/1
	?assertEqual("xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ", lib_hd:readable(lib_hd:pub(lib_hd:derive(path, M, <<"m/0'/1">>)))),
	?assertEqual("xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs", lib_hd:readable(lib_hd:derive(path, M, <<"m/0'/1">>))),

	%% chain m/0h/1/2h
	?assertEqual("xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5", lib_hd:readable(lib_hd:pub(lib_hd:derive(path, M, <<"m/0'/1/2'">>)))),
	?assertEqual("xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM", lib_hd:readable(lib_hd:derive(path, M, <<"m/0'/1/2'">>))),

	%% chain m/0h/1/2h/2
	?assertEqual("xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV", lib_hd:readable(lib_hd:pub(lib_hd:derive(path, M, <<"m/0'/1/2'/2">>)))),
	?assertEqual("xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334", lib_hd:readable(lib_hd:derive(path, M, <<"m/0'/1/2'/2">>))),

	%% chain m/0h/1/2h/2/1000000000
	?assertEqual("xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy", lib_hd:readable(lib_hd:pub(lib_hd:derive(path, M, <<"m/0'/1/2'/2/1000000000">>)))),
	?assertEqual("xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76", lib_hd:readable(lib_hd:derive(path, M, <<"m/0'/1/2'/2/1000000000">>))).


bip32_vectors2() ->
	Master = hexstr_to_bin("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"),
	M = lib_hd:new(Master),
	%% Chain m
	?assertEqual("xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB", lib_hd:readable(lib_hd:pub(M))),
	?assertEqual("xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U", lib_hd:readable(M)),

	%% Chain m/0
	?assertEqual("xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH", lib_hd:readable(lib_hd:pub(lib_hd:derive(path, M, <<"m/0">>)))),
	?assertEqual("xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt", lib_hd:readable(lib_hd:derive(path, M, <<"m/0">>))),

	%% Chain m/0/2147483647h
	?assertEqual("xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a", lib_hd:readable(lib_hd:pub(lib_hd:derive(path, M, <<"m/0/2147483647'">>)))),
	?assertEqual("xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9", lib_hd:readable(lib_hd:derive(path, M, <<"m/0/2147483647'">>))),

	%% Chain m/0/2147483647H/1
	?assertEqual("xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon", lib_hd:readable(lib_hd:pub(lib_hd:derive(path, M, <<"m/0/2147483647'/1">>)))),
	?assertEqual("xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef", lib_hd:readable(lib_hd:derive(path, M, <<"m/0/2147483647'/1">>))),

	%% Chain m/0/2147483647H/1/2147483646H
	?assertEqual("xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL", lib_hd:readable(lib_hd:pub(lib_hd:derive(path, M, <<"m/0/2147483647'/1/2147483646'">>)))),
	?assertEqual("xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc", lib_hd:readable(lib_hd:derive(path, M, <<"m/0/2147483647'/1/2147483646'">>))),

	%% Chain m/0/2147483647H/1/2147483646H/2
	?assertEqual("xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt", lib_hd:readable(lib_hd:pub(lib_hd:derive(path, M, <<"m/0/2147483647'/1/2147483646'/2">>)))),
	?assertEqual("xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j", lib_hd:readable(lib_hd:derive(path, M, <<"m/0/2147483647'/1/2147483646'/2">>))).


public_derivation() ->
	Master = hexstr_to_bin("000102030405060708090a0b0c0d0e0f"),
	M = lib_hd:new(Master),
	PubM = lib_hd:pub(lib_hd:derive(path, M, <<"m/0'/1/2'/2">>)),
	PubC = lib_hd:derive(path, PubM, <<"m/1000000000">>),
	%% chain m/0h/1/2h/2/1000000000
	?assertEqual("xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy", lib_hd:readable(PubC)).

error_derivation() ->
	Master = hexstr_to_bin("000102030405060708090a0b0c0d0e0f"),
	M = lib_hd:new(Master),
	PubM = lib_hd:pub(lib_hd:derive(path, M, <<"m/0'/1/2'">>)),
	?assertThrow(public_key_derivation_error, lib_hd:derive(path, PubM, <<"m/100'">>)).

%% Bip-32 Auditing support
non_hardened_children() ->
	Master = hexstr_to_bin("000102030405060708090a0b0c0d0e0f"),
	M = lib_hd:new(Master),
	%% Secondary account
	PubM = lib_hd:pub(lib_hd:derive(path, M, <<"m/0'/1/2'">>)),
	lib_hd:derive(path, PubM, <<"m/100">>).

serialize() ->
	Master = hexstr_to_bin("000102030405060708090a0b0c0d0e0f"),
	M = lib_hd:new(Master),
	Key = <<"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi">>,
	M = lib_hd:new(Key),
	?assertEqual(iolist_to_binary(lib_hd:readable(M)), Key),
	PubKey = <<"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8">>,
	?assertEqual(lib_hd:readable(lib_hd:pub(M)), binary_to_list(PubKey)),
	PubM = lib_hd:new(PubKey),
	?assertEqual(lib_hd:pub(M), PubM).



hd_test_() -> 
  {foreach,
  fun start/0,
  fun stop/1,
   [
   	    {"Creation", fun create/0},
   	    {"Hmac512", fun hmac512/0},
		{"bip32 test vectors 1", fun bip32_vectors1/0},
		{"bip32 test vectors 2", fun bip32_vectors2/0},
		{"public path derivation", fun public_derivation/0},
		{"error derivations", fun error_derivation/0},
		{"serialization", fun serialize/0},
		{"Bip32 auditing", fun non_hardened_children/0}
   ]
  }.


%% UTIL
%%
hexstr_to_bin(S) when is_binary(S) ->
	hexstr_to_bin(erlang:binary_to_list(S));

hexstr_to_bin(S) ->
  hexstr_to_bin(S, []).
hexstr_to_bin([], Acc) ->
  list_to_binary(lists:reverse(Acc));
hexstr_to_bin([X,Y|T], Acc) ->
  {ok, [V], []} = io_lib:fread("~16u", [X,Y]),
  hexstr_to_bin(T, [V | Acc]).


