%% Copyright 2017, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(gtp_u_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").
-include_lib("gtplib/include/gtp_packet.hrl").
-include("../include/gtp_u_edp.hrl").

-define(TIMEOUT, 2000).
-define(LOCALHOST, {127,0,0,1}).
-define(CLIENT_IP, {127,127,127,127}).
-define(TEST_GSN, ?LOCALHOST).
-define(PROXY_GSN, {127,0,100,1}).
-define(FINAL_GSN, {127,0,200,1}).

-define(equal(Expected, Actual),
    (fun (Expected@@@, Expected@@@) -> true;
	 (Expected@@@, Actual@@@) ->
	     ct:pal("MISMATCH(~s:~b, ~s)~nExpected: ~p~nActual:   ~p~n",
		    [?FILE, ?LINE, ??Actual, Expected@@@, Actual@@@]),
	     false
     end)(Expected, Actual) orelse error(badmatch)).

-define(match(Guard, Expr),
	((fun () ->
		  case (Expr) of
		      Guard -> ok;
		      V -> ct:pal("MISMATCH(~s:~b, ~s)~nExpected: ~p~nActual:   ~s~n",
				   [?FILE, ?LINE, ??Expr, ??Guard,
				    pretty_print(V)]),
			    error(badmatch)
		  end
	  end)())).

-define('Tunnel Endpoint Identifier Data I',	{tunnel_endpoint_identifier_data_i, 0}).

%%%===================================================================
%%% API
%%%===================================================================

-define(TEST_CONFIG,
	[
	 {lager, [{colored, true},
		  {error_logger_redirect, false},
		  %% force lager into async logging, otherwise
		  %% the test will timeout randomly
		  {async_threshold, undefined},
		  {handlers, [{lager_console_backend, info}]}
		 ]},

	 {gtp_u_edp, [{sockets,
		       [{grx, [{ip, ?TEST_GSN}]},
			{'proxy-grx', [{ip, ?PROXY_GSN}]}
		       ]}
		     ]}
	]).

init_per_suite(Config0) ->
    Config = init_ets(Config0),
    [application:load(App) || App <- [lager, gtp_u_edp]],
    meck_init(Config),
    load_config(?TEST_CONFIG),
    {ok, _} = application:ensure_all_started(gtp_u_edp),
    lager_common_test_backend:bounce(debug),
    %% ok = meck:wait(gtp_u_edp, start_link, '_', ?TIMEOUT),
    %% ok = meck:wait(2, gtp_u_edp_port, start_link, '_', ?TIMEOUT),
    Config.

end_per_suite(Config) ->
    meck_unload(Config),
    ?config(table_owner, Config) ! stop,
    [application:stop(App) || App <- [lager, gtp_u_edp]],
    ok.

init_per_testcase(_, Config) ->
    meck_reset(Config),
    Config.

end_per_testcase(_, Config) ->
    Config.

suite() ->
    [{timetrap,{seconds,30}}].

all() ->
    [
     invalid_gtp_pdu,
     invalid_teid,
     echo_request,
     bind,
     clear,
     create_pdp_context,
     create_invalid_pdp_context,
     create_pdp_context_clear,
     delete_pdp_context,
     update_pdp_context,
     forward_data,
     remote_invalid,
     local_invalid
    ].

%%%===================================================================
%%% Init/End helper
%%%===================================================================

ets_owner() ->
    receive
	stop ->
	    exit(normal);
	_ ->
	    ets_owner()
    end.

init_ets(Config) ->
    Pid = spawn(fun ets_owner/0),
    TabId = ets:new(?MODULE, [set, public, named_table, {heir, Pid, []}]),
    ets:insert(TabId, [{seq_no, 1},
		       {restart_counter, 1},
		       {teid, 1}]),
    [{table, TabId}, {table_owner, Pid} | Config].

load_config(AppCfg) ->
    lists:foreach(fun({App, Settings}) ->
			  ct:pal("App: ~p, S: ~p", [App, Settings]),
			  lists:foreach(fun({K,V}) ->
						ct:pal("App: ~p, K: ~p, V: ~p", [App, K, V]),
						application:set_env(App, K, V)
					end, Settings)
		  end, AppCfg),
    ok.

%%%===================================================================
%%% Meck functions for fake the GTP sockets
%%%===================================================================

meck_init(_Config) ->
    ok = meck:new(gtp_u_edp, [passthrough, no_link]),
    ok = meck:new(gtp_u_edp_port, [passthrough, no_link]),
    ok = meck:new(gtp_u_edp_handler, [passthrough, no_link]),
    ok = meck:new(gtp_u_edp_forwarder, [passthrough, no_link]).

meck_reset(_Config) ->
    meck:reset(gtp_u_edp),
    meck:reset(gtp_u_edp_port),
    meck:reset(gtp_u_edp_handler),
    meck:reset(gtp_u_edp_forwarder).

meck_unload(_Config) ->
    meck:unload(gtp_u_edp),
    meck:unload(gtp_u_edp_port),
    meck:unload(gtp_u_edp_handler),
    meck:unload(gtp_u_edp_forwarder).

meck_validate(_Config) ->
    ?equal(true, meck:validate(gtp_u_edp)),
    ?equal(true, meck:validate(gtp_u_edp_port)),
    ?equal(true, meck:validate(gtp_u_edp_handler)),
    ?equal(true, meck:validate(gtp_u_edp_forwarder)).

%%%===================================================================
%%% Tests
%%%===================================================================

%%--------------------------------------------------------------------
invalid_gtp_pdu() ->
    [{doc, "Test that an invalid PDU is silently ignored"
      " and that the GTP socket is not crashing"}].
invalid_gtp_pdu(Config) ->
    S = make_gtp_socket(Config),
    gen_udp:send(S, ?TEST_GSN, ?GTP1u_PORT, <<"TESTDATA">>),

    ?equal({error,timeout}, gen_udp:recv(S, 4096, ?TIMEOUT)),
    meck_validate(Config),
    ok.

invalid_teid() ->
    [{doc, "Test that an PDU with an unknown TEID is silently ignored"
      " and that the GTP socket is not crashing"}].
invalid_teid(Config) ->
    S = make_gtp_socket(Config),

    TEID = get_next_teid(),
    Msg =  #gtp{version = v1, type = g_pdu, tei = TEID, ie = <<"TESTDATA">>},

    ?match(#gtp{version = v1, type = error_indication, tei = 0,
	       ie = #{?'Tunnel Endpoint Identifier Data I' :=
			  #tunnel_endpoint_identifier_data_i{tei = TEID}}},
	   send_recv_pdu(S, Msg)),

    meck_validate(Config),
    ok.

echo_request() ->
    [{doc, "Test that a Echo Request is answered properly"}].
echo_request(Config) ->
    S = make_gtp_socket(Config),

    SeqNo = get_next_seq_no(),
    ReqIEs = [#recovery{restart_counter = 0}],
    Msg = #gtp{version = v1, type = echo_request, tei = 0,
	       seq_no = SeqNo, ie = ReqIEs},

    ?match(#gtp{version = v1, type = echo_response, tei = 0, seq_no = SeqNo},
	   send_recv_pdu(S, Msg)),

    meck_validate(Config),
    ok.

bind() ->
    [{doc, "Test GTP-C to DP bind call"}].
bind(Config) ->
    ?match({ok, _, ?TEST_GSN}, gen_server:call('gtp-u', {bind, grx})),
    ?match({ok, _, ?PROXY_GSN}, gen_server:call('gtp-u', {bind, 'proxy-grx'})),
    ?match({reply, {error, not_found}}, gen_server:call('gtp-u', {bind, 'invalid'})),

    meck_validate(Config),
    ok.

clear() ->
    [{doc, "Test GTP-C to DP clear call"}].
clear(Config) ->
    {ok, Pid, _} = gen_server:call('gtp-u', {bind, grx}),
    ?equal(ok, gen_server:call(Pid, clear)),

    meck_validate(Config),
    ok.

create_pdp_context() ->
    [{doc, "Test GTP-C to DP create_pdp_context call"}].
create_pdp_context(Config) ->
    {ok, Pid, ?TEST_GSN} = gen_server:call('gtp-u', {bind, grx}),
    ok = gen_server:call(Pid, clear),

    PeerIP = ?CLIENT_IP,
    LocalTEI = get_next_teid(),
    RemoteTEI = get_next_teid(),
    FwdRemoteIP = ?FINAL_GSN,
    FwdLocalTEI = get_next_teid(),
    FwdRemoteTEI = get_next_teid(),
    Args = {forward, ['proxy-grx', FwdRemoteIP, FwdLocalTEI, FwdRemoteTEI]},
    Request = {create_pdp_context, PeerIP, LocalTEI, RemoteTEI, Args},

    ?match({ok, _}, gen_server:call(Pid, Request)),
    validate_tunnel(grx, LocalTEI, PeerIP, RemoteTEI),
    validate_tunnel('proxy-grx', FwdLocalTEI, FwdRemoteIP, FwdRemoteTEI),

    ok = gen_server:call(Pid, clear),

    meck_validate(Config),
    ok.

create_invalid_pdp_context() ->
    [{doc, "Test error handling in create_pdp_context call"}].
create_invalid_pdp_context(Config) ->
    {ok, Pid, ?TEST_GSN} = gen_server:call('gtp-u', {bind, grx}),
    ok = gen_server:call(Pid, clear),

    PeerIP = ?CLIENT_IP,
    LocalTEI = get_next_teid(),
    RemoteTEI = get_next_teid(),
    FwdRemoteIP = ?FINAL_GSN,
    FwdLocalTEI = get_next_teid(),
    FwdRemoteTEI = get_next_teid(),

    Args = {forward, ['invalid-grx', FwdRemoteIP, FwdLocalTEI, FwdRemoteTEI]},
    Request = {create_pdp_context, PeerIP, LocalTEI, RemoteTEI, Args},

    ?match({error,{error,invalid_port}}, gen_server:call(Pid, Request)),

    ok = gen_server:call(Pid, clear),

    meck_validate(Config),
    ok.
create_pdp_context_clear() ->
    [{doc, "Test that a DP clear really removes all existing forwarders"}].
create_pdp_context_clear(Config) ->
    {ok, Pid, ?TEST_GSN} = gen_server:call('gtp-u', {bind, grx}),
    ok = gen_server:call(Pid, clear),

    PeerIP = ?CLIENT_IP,
    LocalTEI = get_next_teid(),
    RemoteTEI = get_next_teid(),
    FwdRemoteIP = ?FINAL_GSN,
    FwdLocalTEI = get_next_teid(),
    FwdRemoteTEI = get_next_teid(),
    Args = {forward, ['proxy-grx', FwdRemoteIP, FwdLocalTEI, FwdRemoteTEI]},
    Request = {create_pdp_context, PeerIP, LocalTEI, RemoteTEI, Args},

    ?match({ok, _}, gen_server:call(Pid, Request)),
    validate_tunnel(grx, LocalTEI, PeerIP, RemoteTEI),
    validate_tunnel('proxy-grx', FwdLocalTEI, FwdRemoteIP, FwdRemoteTEI),

    ok = gen_server:call(Pid, clear),

    %% gtp_u_edp:all/0 bypasses the reg server
    ok = meck:wait(gtp_u_edp_forwarder, terminate, '_', ?TIMEOUT),
    ok = meck:wait(4, gtp_u_edp, handle_info, [{'DOWN', '_', '_', '_', normal}, '_'], ?TIMEOUT),
    ?equal([], gtp_u_edp:all()),

    meck_validate(Config),
    ok.

delete_pdp_context() ->
    [{doc, "Test GTP-C to DP delete_pdp_context call"}].
delete_pdp_context(Config) ->
    {ok, Pid, ?TEST_GSN} = gen_server:call('gtp-u', {bind, grx}),
    ok = gen_server:call(Pid, clear),

    PeerIP = ?CLIENT_IP,
    LocalTEI = get_next_teid(),
    InvalidLocalTEI = get_next_teid(),
    RemoteTEI = get_next_teid(),
    FwdRemoteIP = ?FINAL_GSN,
    FwdLocalTEI = get_next_teid(),
    FwdRemoteTEI = get_next_teid(),
    Args = {forward, ['proxy-grx', FwdRemoteIP, FwdLocalTEI, FwdRemoteTEI]},
    Request0 = {create_pdp_context, PeerIP, LocalTEI, RemoteTEI, Args},
    Request1 = {delete_pdp_context, PeerIP, InvalidLocalTEI, RemoteTEI, Args},
    Request2 = {delete_pdp_context, PeerIP, LocalTEI, RemoteTEI, Args},

    ?match({ok, _}, gen_server:call(Pid, Request0)),
    validate_tunnel(grx, LocalTEI, PeerIP, RemoteTEI),
    validate_tunnel('proxy-grx', FwdLocalTEI, FwdRemoteIP, FwdRemoteTEI),

    ?match({error,not_found}, gen_server:call(Pid, Request1)),
    validate_tunnel(grx, LocalTEI, PeerIP, RemoteTEI),
    validate_tunnel('proxy-grx', FwdLocalTEI, FwdRemoteIP, FwdRemoteTEI),

    ?equal(ok, gen_server:call(Pid, Request2)),

    %% gtp_u_edp:all/0 bypasses the reg server
    ok = meck:wait(gtp_u_edp_forwarder, terminate, '_', ?TIMEOUT),
    ok = meck:wait(4, gtp_u_edp, handle_info, [{'DOWN', '_', '_', '_', normal}, '_'], ?TIMEOUT),
    ?equal([], gtp_u_edp:all()),

    meck_validate(Config),
    ok.

update_pdp_context() ->
    [{doc, "Test GTP-C to DP update_pdp_context call"}].
update_pdp_context(Config) ->
    {ok, Pid, ?TEST_GSN} = gen_server:call('gtp-u', {bind, grx}),
    ok = gen_server:call(Pid, clear),

    PeerIP = ?CLIENT_IP,
    LocalTEI = get_next_teid(),
    InvalidLocalTEI = get_next_teid(),
    RemoteTEI = get_next_teid(),
    FwdRemoteIP = ?FINAL_GSN,
    FwdLocalTEI = get_next_teid(),
    FwdRemoteTEI = get_next_teid(),
    Args = {forward, ['proxy-grx', FwdRemoteIP, FwdLocalTEI, FwdRemoteTEI]},
    Request0 = {create_pdp_context, PeerIP, LocalTEI, RemoteTEI, Args},

    UpdPeerIP = ?CLIENT_IP,
    UpdRemoteTEI = get_next_teid(),
    Request1 = {update_pdp_context, UpdPeerIP, InvalidLocalTEI, UpdRemoteTEI, Args},
    Request2 = {update_pdp_context, UpdPeerIP, LocalTEI, UpdRemoteTEI, Args},
    Request3 = {delete_pdp_context, UpdPeerIP, LocalTEI, UpdRemoteTEI, Args},

    ?match({ok, _}, gen_server:call(Pid, Request0)),
    validate_tunnel(grx, LocalTEI, PeerIP, RemoteTEI),
    validate_tunnel('proxy-grx', FwdLocalTEI, FwdRemoteIP, FwdRemoteTEI),

    ?match({error,not_found}, gen_server:call(Pid, Request1)),
    validate_tunnel(grx, LocalTEI, PeerIP, RemoteTEI),
    validate_tunnel('proxy-grx', FwdLocalTEI, FwdRemoteIP, FwdRemoteTEI),

    ?match(ok, gen_server:call(Pid, Request2)),
    validate_tunnel(grx, LocalTEI, UpdPeerIP, UpdRemoteTEI),
    validate_tunnel('proxy-grx', FwdLocalTEI, FwdRemoteIP, FwdRemoteTEI),

    ?equal(ok, gen_server:call(Pid, Request3)),

    %% gtp_u_edp:all/0 bypasses the reg server
    ok = meck:wait(gtp_u_edp_forwarder, terminate, '_', ?TIMEOUT),
    ok = meck:wait(4, gtp_u_edp, handle_info, [{'DOWN', '_', '_', '_', normal}, '_'], ?TIMEOUT),
    ?equal([], gtp_u_edp:all()),

    meck_validate(Config),
    ok.

forward_data() ->
    [{doc, "Test forwarding data works"}].
forward_data(Config) ->
    {ok, Pid, ?TEST_GSN} = gen_server:call('gtp-u', {bind, grx}),
    ok = gen_server:call(Pid, clear),

    PeerIP = ?CLIENT_IP,
    LocalTEI = get_next_teid(),
    RemoteTEI = get_next_teid(),
    FwdRemoteIP = ?FINAL_GSN,
    FwdLocalTEI = get_next_teid(),
    FwdRemoteTEI = get_next_teid(),
    Args = {forward, ['proxy-grx', FwdRemoteIP, FwdLocalTEI, FwdRemoteTEI]},
    Request0 = {create_pdp_context, PeerIP, LocalTEI, RemoteTEI, Args},
    Request1 = {delete_pdp_context, PeerIP, LocalTEI, RemoteTEI, Args},

    ?match({ok, _}, gen_server:call(Pid, Request0)),
    validate_tunnel(grx, LocalTEI, PeerIP, RemoteTEI),
    validate_tunnel('proxy-grx', FwdLocalTEI, FwdRemoteIP, FwdRemoteTEI),

    EchoFun =
	fun(Socket) ->
		Msg = recv_pdu(Socket, ?PROXY_GSN, ?TIMEOUT),
		?match(#gtp{type = g_pdu, tei = FwdRemoteTEI}, Msg),
		send_pdu(Socket, ?PROXY_GSN, Msg#gtp{tei = FwdLocalTEI}),
		done
	end,
    {ok, EchoPid} = proc_lib:start_link(?MODULE, remote_server, [Config, self(), EchoFun]),

    S = make_gtp_socket(Config),

    Msg = #gtp{version = v1, type = g_pdu, tei = LocalTEI, ie = <<"TESTDATA">>},
    ?match(#gtp{type = g_pdu, tei = RemoteTEI}, send_recv_pdu(S, Msg)),

    receive
	{EchoPid, done} -> ok
    after ?TIMEOUT ->
	    ct:fail(timeout)
    end,

    ?equal(ok, gen_server:call(Pid, Request1)),

    %% gtp_u_edp:all/0 bypasses the reg server
    ok = meck:wait(gtp_u_edp_forwarder, terminate, '_', ?TIMEOUT),
    ok = meck:wait(4, gtp_u_edp, handle_info, [{'DOWN', '_', '_', '_', normal}, '_'], ?TIMEOUT),
    ?equal([], gtp_u_edp:all()),

    meck_validate(Config),
    ok.

remote_invalid() ->
    [{doc, "Test that a error returned from the remote is handled"}].
remote_invalid(Config) ->
    {ok, Pid, ?TEST_GSN} = gen_server:call('gtp-u', {bind, grx}),
    ok = gen_server:call(Pid, clear),

    PeerIP = ?CLIENT_IP,
    LocalTEI = get_next_teid(),
    RemoteTEI = get_next_teid(),
    FwdRemoteIP = ?FINAL_GSN,
    FwdLocalTEI = get_next_teid(),
    FwdRemoteTEI = get_next_teid(),
    Args = {forward, ['proxy-grx', FwdRemoteIP, FwdLocalTEI, FwdRemoteTEI]},
    Request0 = {create_pdp_context, PeerIP, LocalTEI, RemoteTEI, Args},
    Request1 = {delete_pdp_context, PeerIP, LocalTEI, RemoteTEI, Args},

    ?match({ok, _}, gen_server:call(Pid, Request0)),
    validate_tunnel(grx, LocalTEI, PeerIP, RemoteTEI),
    validate_tunnel('proxy-grx', FwdLocalTEI, FwdRemoteIP, FwdRemoteTEI),

    EchoFun =
	fun(Socket) ->
		Msg = recv_pdu(Socket, ?PROXY_GSN, ?TIMEOUT),
		?match(#gtp{type = g_pdu, tei = FwdRemoteTEI}, Msg),

		RespIE = [#tunnel_endpoint_identifier_data_i{tei = FwdRemoteTEI}],
		Resp = #gtp{version = v1, type = error_indication, tei = 0, ie = RespIE},
		send_pdu(Socket, ?PROXY_GSN, Resp),
		done
	end,
    {ok, EchoPid} = proc_lib:start_link(?MODULE, remote_server, [Config, self(), EchoFun]),

    S = make_gtp_socket(Config),

    Msg = #gtp{version = v1, type = g_pdu, tei = LocalTEI, ie = <<"TESTDATA">>},
    ?match(#gtp{version = v1, type = error_indication, tei = 0,
		ie = #{?'Tunnel Endpoint Identifier Data I' :=
			   #tunnel_endpoint_identifier_data_i{tei = LocalTEI}}},
	   send_recv_pdu(S, Msg)),

    receive
	{EchoPid, done} -> ok
    after ?TIMEOUT ->
	    ct:fail(timeout)
    end,

    ?equal(ok, gen_server:call(Pid, Request1)),

    %% gtp_u_edp:all/0 bypasses the reg server
    ok = meck:wait(gtp_u_edp_forwarder, terminate, '_', ?TIMEOUT),
    ok = meck:wait(4, gtp_u_edp, handle_info, [{'DOWN', '_', '_', '_', normal}, '_'], ?TIMEOUT),
    ?equal([], gtp_u_edp:all()),

    meck_validate(Config),
    ok.

local_invalid() ->
    [{doc, "Test that a error is forwardedto the remote is handled"}].
local_invalid(Config) ->
    {ok, Pid, ?TEST_GSN} = gen_server:call('gtp-u', {bind, grx}),
    ok = gen_server:call(Pid, clear),

    PeerIP = ?CLIENT_IP,
    LocalTEI = get_next_teid(),
    RemoteTEI = get_next_teid(),
    FwdRemoteIP = ?FINAL_GSN,
    FwdLocalTEI = get_next_teid(),
    FwdRemoteTEI = get_next_teid(),
    Args = {forward, ['proxy-grx', FwdRemoteIP, FwdLocalTEI, FwdRemoteTEI]},
    Request0 = {create_pdp_context, PeerIP, LocalTEI, RemoteTEI, Args},
    Request1 = {delete_pdp_context, PeerIP, LocalTEI, RemoteTEI, Args},

    ?match({ok, _}, gen_server:call(Pid, Request0)),
    validate_tunnel(grx, LocalTEI, PeerIP, RemoteTEI),
    validate_tunnel('proxy-grx', FwdLocalTEI, FwdRemoteIP, FwdRemoteTEI),

    EchoFun =
	fun(Socket) ->
		Msg = recv_pdu(Socket, ?PROXY_GSN, ?TIMEOUT),
		?match(#gtp{type = error_indication, tei = 0,
			    ie = #{?'Tunnel Endpoint Identifier Data I' :=
				       #tunnel_endpoint_identifier_data_i{tei = FwdLocalTEI}}},
		       Msg),
		done
	end,
    {ok, EchoPid} = proc_lib:start_link(?MODULE, remote_server, [Config, self(), EchoFun]),

    S = make_gtp_socket(Config),

    MsgIE = [#tunnel_endpoint_identifier_data_i{tei = RemoteTEI}],
    Msg = #gtp{version = v1, type = error_indication, tei = 0, ie = MsgIE},
    send_pdu(S, Msg),

    receive
	{EchoPid, done} -> ok
    after ?TIMEOUT ->
	    ct:fail(timeout)
    end,

    ?equal(ok, gen_server:call(Pid, Request1)),

    %% gtp_u_edp:all/0 bypasses the reg server
    ok = meck:wait(gtp_u_edp_forwarder, terminate, '_', ?TIMEOUT),
    ok = meck:wait(4, gtp_u_edp, handle_info, [{'DOWN', '_', '_', '_', normal}, '_'], ?TIMEOUT),
    ?equal([], gtp_u_edp:all()),

    meck_validate(Config),
    ok.

remote_server(Config, Parent, Fun) ->
    Socket = make_gtp_socket(Config, ?FINAL_GSN),
    proc_lib:init_ack(Parent, {ok, self()}),
    Reply = Fun(Socket),
    gen_udp:close(Socket),
    Parent ! {self(), Reply}.

%%%===================================================================
%%% I/O and socket functions
%%%===================================================================

make_gtp_socket(Config) ->
    make_gtp_socket(Config, ?CLIENT_IP).

make_gtp_socket(_Config, IP) ->
    {ok, S} = gen_udp:open(?GTP1u_PORT, [{ip, IP}, {active, false},
					 binary, {reuseaddr, true}]),
    S.

send_pdu(S, Msg) ->
    send_pdu(S, ?TEST_GSN, Msg).

send_pdu(S, Peer, Msg) ->
    Data = gtp_packet:encode(Msg),
    ok = gen_udp:send(S, Peer, ?GTP1u_PORT, Data).

send_recv_pdu(S, Msg) ->
    send_recv_pdu(S, Msg, ?TIMEOUT).

send_recv_pdu(S, Msg, Timeout) ->
    send_recv_pdu(S, ?TEST_GSN, Msg, Timeout).

send_recv_pdu(S, Peer, Msg, Timeout) ->
    send_pdu(S, Peer, Msg),
    recv_pdu(S, Peer, Msg#gtp.seq_no, Timeout).

recv_pdu(S, Timeout) ->
    recv_pdu(S, ?TEST_GSN, Timeout).

recv_pdu(S, Peer, Timeout) ->
    recv_pdu(S, Peer, undefined, Timeout).

recv_pdu(S, Peer, SeqNo, Timeout) ->
    recv_pdu(S, Peer, SeqNo, Timeout, fun(Reason) -> ct:fail(Reason) end).

recv_pdu(_, _Peer, _SeqNo, Timeout, Fail) when Timeout =< 0 ->
    recv_pdu_fail(Fail, timeout);
recv_pdu(S, Peer, SeqNo, Timeout, Fail) ->
    Now = erlang:monotonic_time(millisecond),
    case gen_udp:recv(S, 4096, Timeout) of
	{ok, {Peer, _, Response}} ->
	    recv_pdu_msg(Response, Now, S, Peer, SeqNo, Timeout, Fail);
	{error, Error} ->
	    recv_pdu_fail(Fail, Error);
	Unexpected ->
	    recv_pdu_fail(Fail, Unexpected)
    end.

recv_pdu_msg(Response, At, S, Peer, SeqNo, Timeout, Fail) ->
    ct:pal("Msg: ~s", [pretty_print((catch gtp_packet:decode(Response)))]),
    case gtp_packet:decode(Response) of
	#gtp{type = echo_request} = Msg ->
	    Resp = Msg#gtp{type = echo_response, ie = []},
	    send_pdu(S, Resp),
	    NewTimeout = Timeout - (erlang:monotonic_time(millisecond) - At),
	    recv_pdu(S, Peer, SeqNo, NewTimeout, Fail);
	#gtp{seq_no = SeqNo} = Msg
	  when is_integer(SeqNo) ->
	    Msg;

	Msg ->
	    Msg
    end.

recv_pdu_fail(Fail, Why) when is_function(Fail) ->
    Fail(Why);
recv_pdu_fail(Fail, Why) ->
    {Fail, Why}.

%%%===================================================================
%%% Record formating
%%%===================================================================

pretty_print(Record) ->
    io_lib_pretty:print(Record, fun pretty_print/2).

pretty_print(gtp, N) ->
    N = record_info(size, gtp) - 1,
    record_info(fields, gtp);
pretty_print(_, _) ->
    no.

%%%===================================================================
%%% TEID and SeqNo functions
%%%===================================================================

get_next_teid() ->
    ets:update_counter(?MODULE, teid, 1) rem 16#100000000.

get_next_seq_no() ->
    ets:update_counter(?MODULE, seq_no, 1) rem 16#10000.

%%%===================================================================
%%% Internal functions
%%%===================================================================

make_g_pdu(TEID, Bin) ->
    #gtp{version = v1, type = g_pdu, tei = TEID, ie = Bin}.

validate_tunnel(Name, LocalTEI, RemoteIP, RemoteTEI) ->
    ?match(Pid when is_pid(Pid), gtp_u_edp:lookup({Name, LocalTEI})),
    ?match(Pid when is_pid(Pid), gtp_u_edp:lookup({Name, {remote, RemoteIP, RemoteTEI}})),
    ok.
