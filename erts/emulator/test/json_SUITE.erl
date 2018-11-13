-module(json_SUITE).

-export([all/0, suite/0, groups/0, init_per_suite/1, end_per_suite/1,
         init_per_group/2, end_per_group/2,
         init_per_testcase/2, end_per_testcase/2,
         basic_types/1, integers/1, lists/1,
         objects_proplist/1, objects_flatmap/1, objects_hamt/1, objects_atomkey/1,
         unicode/1, binaries/1, bigints/1,
         preencoded/1, errors/1]).

-include_lib("eunit/include/eunit.hrl").

suite() -> [{ct_hooks,[ts_install_cth]},
            {timetrap,{minutes,1}}].

all() ->
    [basic_types, integers, lists,
     objects_proplist, objects_flatmap, objects_hamt, objects_atomkey,
     unicode, binaries, bigints, preencoded, errors].

groups() ->
    [].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(_GroupName, Config) ->
    Config.

end_per_group(_GroupName, Config) ->
    Config.

init_per_testcase(Func, Config) when is_atom(Func), is_list(Config) ->
    Config.

end_per_testcase(_Func, _Config) ->
    ok.

%% ts:run(emulator, json_SUITE, [ batch ]).

basic_types(Config) when is_list(Config) ->
    <<"true">> = erlang:term_to_json(true),
    <<"false">> = erlang:term_to_json(false),
    <<"null">> = erlang:term_to_json(null),
    <<"1">> = erlang:term_to_json(1),
    <<"1.1">> = erlang:term_to_json(1.1),
    <<"\"apple\"">> = erlang:term_to_json(<<"apple">>),
    ok.

integers(Config) when is_list(Config) ->
    <<"0">> = erlang:term_to_json(0),
    <<"1">> = erlang:term_to_json(1),
    <<"-1">> = erlang:term_to_json(-1),
    <<"9">> = erlang:term_to_json(9),
    <<"10">> = erlang:term_to_json(10),
    <<"99">> = erlang:term_to_json(99),
    <<"-100">> = erlang:term_to_json(-100),
    <<"1234">> = erlang:term_to_json(1234),
    <<"4321">> = erlang:term_to_json(4321),
    <<"5678">> = erlang:term_to_json(5678),
    <<"8765">> = erlang:term_to_json(8765),
    <<"9999">> = erlang:term_to_json(9999),
    <<"10000">> = erlang:term_to_json(10000),
    <<"100000">> = erlang:term_to_json(100000),
    <<"1000000">> = erlang:term_to_json(1000000),
    <<"10000000">> = erlang:term_to_json(10000000),
    <<"100000000">> = erlang:term_to_json(100000000),
    <<"1000000000">> = erlang:term_to_json(1000000000),
    <<"1234567890">> = erlang:term_to_json(1234567890),
    <<"2147483647">> = erlang:term_to_json(2147483647),
    <<"2147483648">> = erlang:term_to_json(2147483648),
    <<"-2147483647">> = erlang:term_to_json(-2147483647),
    <<"-2147483648">> = erlang:term_to_json(-2147483648),
    <<"-2147483649">> = erlang:term_to_json(-2147483649),
    << "576460752303423487">> = erlang:term_to_json(576460752303423487), % 2^59 - 1.
    <<"-576460752303423488">> = erlang:term_to_json(-576460752303423488), % - 2^59.

    <<"1011121314">> = erlang:term_to_json(1011121314),
    <<"1516171819">> = erlang:term_to_json(1516171819),
    <<"2021222324">> = erlang:term_to_json(2021222324),
    <<"2526272829">> = erlang:term_to_json(2526272829),
    <<"3031323334">> = erlang:term_to_json(3031323334),
    <<"3536373839">> = erlang:term_to_json(3536373839),
    <<"4041424344">> = erlang:term_to_json(4041424344),
    <<"4546474849">> = erlang:term_to_json(4546474849),
    <<"5051525354">> = erlang:term_to_json(5051525354),
    <<"5556575859">> = erlang:term_to_json(5556575859),
    <<"6061626364">> = erlang:term_to_json(6061626364),
    <<"6566676869">> = erlang:term_to_json(6566676869),
    <<"7071727374">> = erlang:term_to_json(7071727374),
    <<"7576777879">> = erlang:term_to_json(7576777879),
    <<"8081828384">> = erlang:term_to_json(8081828384),
    <<"8586878889">> = erlang:term_to_json(8586878889),
    <<"9091929394">> = erlang:term_to_json(9091929394),
    <<"9596979899">> = erlang:term_to_json(9596979899),
    <<"990001020304">> = erlang:term_to_json(990001020304),
    <<"990506070809">> = erlang:term_to_json(990506070809),
    ok.

lists(Config) when is_list(Config) ->
    <<"[]">> = erlang:term_to_json([]),
    <<"[true]">> = erlang:term_to_json([true]),
    <<"[1]">> = erlang:term_to_json([1]),
    <<"[0.5]">> = erlang:term_to_json([0.5]),
    <<"[1,2]">> = erlang:term_to_json([1, 2]),
    <<"[1,2,3]">> = erlang:term_to_json([1, 2, 3]),
    <<"[true,2,\"three\"]">> = erlang:term_to_json([true, 2, <<"three">>]),
    <<"[1,2,[3,4,5],6,[[7]],[8,[9,[10],11,12]]]">> =
        erlang:term_to_json([1, 2, [3, 4, 5], 6, [[7]], [8, [9, [10], 11, 12]]]),
    ok.

objects_proplist(Config) when is_list(Config) ->
    <<"{}">> = erlang:term_to_json({[]}),
    <<"{\"one\":1}">> = erlang:term_to_json({[{<<"one">>, 1}]}),
    <<"{\"one\":1,\"two\":2}">> = erlang:term_to_json({[{<<"one">>, 1}, {<<"two">>, 2}]}),
    <<"{\"one\":1,\"two\":2,\"three\":3}">> = erlang:term_to_json({[{<<"one">>, 1}, {<<"two">>, 2}, {<<"three">>, 3}]}),
    <<"{\"empty\":[]}">> = erlang:term_to_json({[{<<"empty">>, []}]}),
    <<"{\"list\":[1,2,3]}">> = erlang:term_to_json({[{<<"list">>, [1, 2, 3]}]}),
    <<"{\"empty\":{}}">> = erlang:term_to_json({[{<<"empty">>, {[]}}]}),
    <<"{\"object\":{\"1\":\"one\"}}">> = erlang:term_to_json({[{<<"object">>, {[{<<"1">>,<<"one">>}]}}]}),
    ok.

objects_flatmap(Config) when is_list(Config) ->
    <<"{}">> = erlang:term_to_json(#{}),
    <<"{\"a\":\"apple\"}">> = erlang:term_to_json(#{<<"a">> => <<"apple">>}),
    <<"{\"a\":\"apple\",\"b\":\"banana\"}">> = erlang:term_to_json(#{<<"a">> => <<"apple">>, <<"b">> => <<"banana">>}),
    ok.

objects_hamt(Config) when is_list(Config) ->
    %% The map implementation switches to HAMT at 32 elements.
    MakeMapFun =
        fun (Values) ->
                maps:from_list(
                  lists:map(fun (N) when is_integer(N) -> {integer_to_binary(N), N};
                                (B) when is_binary(B)  -> {B, B}
                            end, Values))
        end,
    %% This may cause the test to fail if maps:to_list visits the map elements
    %% in a different order than the code in enc_json_int.
    MakeJsonFun =
        fun (Map) ->
                list_to_binary(
                  [ ${,
                    lists:join($,,
                               lists:map(
                                 fun ({K, V}) -> [ encode_to_binary(K), $:, encode_natural(V) ] end,
                                 maps:to_list(Map))),
                    $}
                  ])
        end,

    V1 = lists:seq(1, 33),
    M1 = MakeMapFun(V1),
    J1 = MakeJsonFun(M1),
    %% io:format(user, ">> ~p\n", [ J1 ]),
    J1 = erlang:term_to_json(MakeMapFun(V1)),
    %% io:format(user, ">> ~p\n", [ J1A ]),
    %% MM1 = maps:from_list(mochijson2:decode(J1A, [ {format, proplist} ])),
    %% io:format(user, "x ~p\n  ~p\n", [ M1, MM1 ]),

    V2 = lists:seq(1, 128),
    M2 = MakeMapFun(V2),
    J2 = MakeJsonFun(M2),
    J2 = erlang:term_to_json(MakeMapFun(V2)),
    %% io:format(user, ">> ~p\n", [ J2 ]),
    %% MM2 = maps:from_list(mochijson2:decode(J2, [ {format, proplist} ])),
    %% io:format(user, "x ~p\n  ~p\n", [ M2, MM2 ]),

    ok.

objects_atomkey(Config) when is_list(Config) ->
    <<"{\"a\":\"apple\"}">> = erlang:term_to_json({[{a, <<"apple">>}]}),
    <<"{\"1\":\"one\"}">> = erlang:term_to_json({[{'1', <<"one">>}]}),
    Ole = <<"¡olé!"/utf8>>,
    <<"{\"¡olé!\":\"bravo!\"}"/utf8>> = erlang:term_to_json({[{Ole, <<"bravo!">>}]}),
    <<"{\"a\":\"apple\"}">> = erlang:term_to_json(#{a => <<"apple">>}),
    ok.

unicode(Config) when is_list(Config) ->
    <<"\"\\u0000\"">> = erlang:term_to_json(list_to_binary([0])),
    <<"\"\\b\"">> = erlang:term_to_json(<<"\b">>),
    <<"\"\\n\"">> = erlang:term_to_json(<<"\n">>),
    <<"\"\\r\"">> = erlang:term_to_json(<<"\r">>),
    <<"\"\\t\"">> = erlang:term_to_json(<<"\t">>),
    <<"\"\\\"\"">> = erlang:term_to_json(<<"\"">>),
    <<"\"\\\\\"">> = erlang:term_to_json(<<"\\">>),
    <<"\"say \\\"hello, world\\n\\\", he said\"">> =
        erlang:term_to_json(<<"say \"hello, world\n\", he said">>),
    %% <<"\"<html><p>★¡Héllŏ, wōrłd!★<br />◕‿-</p></html>\""/utf8>> =
    <<34,60,104,116,109,108,62,60,112,62,226,152,133,194,161,
      72,195,169,108,108,197,143,44,32,119,197,141,114,197,
      130,100,33,226,152,133,60,98,114,32,47,62,226,151,149,
      226,128,191,45,60,47,112,62,60,47,104,116,109,108,62,34>> =
        erlang:term_to_json(<<"<html><p>★¡Héllŏ, wōrłd!★<br />◕‿-</p></html>"/utf8>>),
    ok.

binaries(Config) when is_list(Config) ->
    %% Encode an aligned sub-binary.
    <<_:5/binary, Str1:5/binary, _:5/binary>> = <<"abcdefghijklmno">>,
    <<"\"fghij\"">> = erlang:term_to_json(Str1),

    %% Encode a non-aligned binary.
    <<_:4, Str2:5/binary, _:4>> = <<0:4, "hello", 0:4>>,
    <<"\"hello\"">> = erlang:term_to_json(Str2),

    %% Encode a long binary.
    Str3 = list_to_binary(lists:duplicate(10000, list_to_binary(lists:seq($a, $z)))),
    E3 = <<$", Str3/binary, $">>,
    A3 = erlang:term_to_json(Str3),
    ?assertEqual(size(E3), size(A3)),
    ?assertEqual(E3, A3),

    garbage_collect(),

    ok.

bigints(Config) when is_list(Config) ->
    <<"1208925819614629174706176">> = erlang:term_to_json(1 bsl 80),
    <<"-604462909807314587353088">> = erlang:term_to_json(- 1 bsl 79),
    ok.

preencoded(Config) when is_list(Config) ->
    <<"test">> = erlang:term_to_json({json, <<"test">>}),
    <<"[1]">> = erlang:term_to_json([{json, <<"1">>}]),
    <<"[1,2,3]">> = erlang:term_to_json([{json, <<"1,2,3">>}]),
    <<"[1,2,3]">> = erlang:term_to_json([1, {json, <<"2,3">>}]),
    <<"[1,2,3]">> = erlang:term_to_json([{json, <<"1,2">>}, 3]),
    <<"[1,2,3]">> = erlang:term_to_json([1, {json, <<"2">>}, 3]),
    <<"{test}">> = erlang:term_to_json({[{json, <<"test">>}]}),
    <<"{\"t\":test}">> = erlang:term_to_json({[{<<"t">>, {json, <<"test">>}}]}),
    <<"{\"a\":1,\"b\":2}">> = erlang:term_to_json({[{json, <<"\"a\":1">>}, {<<"b">>, 2}]}),
    <<"{\"a\":1,\"b\":2}">> = erlang:term_to_json({[{<<"a">>, 1}, {json, <<"\"b\":2">>}]}),
    <<"{test}">> = erlang:term_to_json(#{json => <<"test">>}),
    LongBinary = list_to_binary([$", lists:duplicate(1000, <<"0123456789">>), $"]),
    LongBinaryExpect = <<$[, LongBinary/binary, $]>>,
    LongBinaryActual = erlang:term_to_json([{json, LongBinary}]),
    ?assertEqual(LongBinaryExpect, LongBinaryActual),
    ok.

errors(Config) when is_list(Config) ->
    ?assertError(badarg, erlang:term_to_json(a)),
    ?assertError(badarg, erlang:term_to_json([ 1 | 2 ])),
    ?assertError(badarg, erlang:term_to_json({[true]})),
    ?assertError(badarg, erlang:term_to_json({[{<<"a">>}]})),
    ?assertError(badarg, erlang:term_to_json({[{<<"a">>, 1, 2}]})),
    ok.

encode_to_binary(I) when is_integer(I) -> [ $", integer_to_binary(I), $" ];
encode_to_binary(B) when is_binary(B)  -> [ $", B, $" ].

encode_natural(I) when is_integer(I) -> integer_to_binary(I);
encode_natural(B) when is_binary(B) -> [ $", B, $" ].
