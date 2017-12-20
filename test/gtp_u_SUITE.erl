%% Copyright 2017, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(gtp_u_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").
-include_lib("gtplib/include/gtp_packet.hrl").
-include_lib("pfcplib/include/pfcp_packet.hrl").
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
		  {handlers, [{lager_console_backend, [{level, info}]}]}
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
     session_establishment_request,
     session_establishment_request_invalid_if,
     session_establishment_request_clear,
     session_deletion_request,
     session_modification_request,
     forward_data,
     query_usage_report,
     error_indication
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
    ok = meck:new(gtp_u_edp_forwarder, [passthrough, no_link]).

meck_reset(_Config) ->
    meck:reset(gtp_u_edp),
    meck:reset(gtp_u_edp_port),
    meck:reset(gtp_u_edp_forwarder).

meck_unload(_Config) ->
    meck:unload(gtp_u_edp),
    meck:unload(gtp_u_edp_port),
    meck:unload(gtp_u_edp_forwarder).

meck_validate(_Config) ->
    ?equal(true, meck:validate(gtp_u_edp)),
    ?equal(true, meck:validate(gtp_u_edp_port)),
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
    S1 = make_gtp_socket(Config, ?CLIENT_IP, ?GTP1u_PORT),
    S2 = make_gtp_socket(Config, ?CLIENT_IP, 0),

    TEID = get_next_teid(),
    Msg =  #gtp{version = v1, type = g_pdu, tei = TEID, ie = <<"TESTDATA">>},
    send_pdu(S2, Msg),

    ?match(#gtp{version = v1, type = error_indication,
		tei = 0, seq_no = undefined,
		ie = #{?'Tunnel Endpoint Identifier Data I' :=
			   #tunnel_endpoint_identifier_data_i{tei = TEID}}},
	   recv_pdu(S1, ?TIMEOUT)),

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

session_establishment_request() ->
    [{doc, "CP to DP Session Establishment Request"}].
session_establishment_request(Config) ->
    SEID = get_next_teid(),
    LeftIntf = 'grx',
    LeftTEI = get_next_teid(),
    LeftPeerIP = ?CLIENT_IP,
    LeftPeerTEI = get_next_teid(),
    RightIntf = 'proxy-grx',
    RightTEI = get_next_teid(),
    RightPeerIP = ?FINAL_GSN,
    RightPeerTEI = get_next_teid(),

    {ok, Pid, ?TEST_GSN} = gen_server:call('gtp-u', {bind, LeftIntf}),
    ok = gen_server:call(Pid, clear),

    Request = make_forward_session(
		SEID,
		LeftIntf,  LeftTEI,  LeftPeerIP,  LeftPeerTEI,
		RightIntf, RightTEI, RightPeerIP, RightPeerTEI),

    ?match({ok, _}, gen_server:call(Pid, Request)),
    validate_tunnel(LeftIntf,  LeftTEI,  LeftPeerIP,  LeftPeerTEI),
    validate_tunnel(RightIntf, RightTEI, RightPeerIP, RightPeerTEI),

    ok = gen_server:call(Pid, clear),

    meck_validate(Config),
    ok.

session_establishment_request_invalid_if() ->
    [{doc, "CP to DP Session Establishment Request with an Invalid Interface"}].
session_establishment_request_invalid_if(Config) ->
    SEID = get_next_teid(),
    LeftIntf = 'grx',
    LeftTEI = get_next_teid(),
    LeftPeerIP = ?CLIENT_IP,
    LeftPeerTEI = get_next_teid(),
    RightIntf = 'invalid-grx',
    RightTEI = get_next_teid(),
    RightPeerIP = ?FINAL_GSN,
    RightPeerTEI = get_next_teid(),

    {ok, Pid, ?TEST_GSN} = gen_server:call('gtp-u', {bind, LeftIntf}),
    ok = gen_server:call(Pid, clear),

    Request = make_forward_session(
		SEID,
		LeftIntf,  LeftTEI,  LeftPeerIP,  LeftPeerTEI,
		RightIntf, RightTEI, RightPeerIP, RightPeerTEI),

    ?match({error,{error,invalid_port}}, gen_server:call(Pid, Request)),

    ok = gen_server:call(Pid, clear),

    meck_validate(Config),
    ok.

session_establishment_request_clear() ->
    [{doc, "DP clear removes all existing forwarders"}].
session_establishment_request_clear(Config) ->
    SEID = get_next_teid(),
    LeftIntf = 'grx',
    LeftTEI = get_next_teid(),
    LeftPeerIP = ?CLIENT_IP,
    LeftPeerTEI = get_next_teid(),
    RightIntf = 'proxy-grx',
    RightTEI = get_next_teid(),
    RightPeerIP = ?FINAL_GSN,
    RightPeerTEI = get_next_teid(),

    {ok, Pid, ?TEST_GSN} = gen_server:call('gtp-u', {bind, LeftIntf}),
    ok = gen_server:call(Pid, clear),

    Request = make_forward_session(
		SEID,
		LeftIntf,  LeftTEI,  LeftPeerIP,  LeftPeerTEI,
		RightIntf, RightTEI, RightPeerIP, RightPeerTEI),

    ?match({ok, _}, gen_server:call(Pid, Request)),
    validate_tunnel(LeftIntf,  LeftTEI,  LeftPeerIP,  LeftPeerTEI),
    validate_tunnel(RightIntf, RightTEI, RightPeerIP, RightPeerTEI),

    ok = gen_server:call(Pid, clear),

    %% gtp_u_edp:all/0 bypasses the reg server
    ok = meck:wait(gtp_u_edp_forwarder, terminate, '_', ?TIMEOUT),
    ok = meck:wait(5, gtp_u_edp, handle_info, [{'DOWN', '_', '_', '_', normal}, '_'], ?TIMEOUT),
    ?equal([], gtp_u_edp:all()),

    meck_validate(Config),
    ok.

session_deletion_request() ->
    [{doc, "CP to DP Session Deletion Request"}].
session_deletion_request(Config) ->
    SEID = get_next_teid(),
    InvalidSEID = get_next_teid(),
    LeftIntf = 'grx',
    LeftTEI = get_next_teid(),
    LeftPeerIP = ?CLIENT_IP,
    LeftPeerTEI = get_next_teid(),
    RightIntf = 'proxy-grx',
    RightTEI = get_next_teid(),
    RightPeerIP = ?FINAL_GSN,
    RightPeerTEI = get_next_teid(),

    {ok, Pid, ?TEST_GSN} = gen_server:call('gtp-u', {bind, LeftIntf}),
    ok = gen_server:call(Pid, clear),

    Request1 = make_forward_session(
		 SEID,
		 LeftIntf,  LeftTEI,  LeftPeerIP,  LeftPeerTEI,
		 RightIntf, RightTEI, RightPeerIP, RightPeerTEI),
    Request2 = make_pfcp(session_deletion_request, InvalidSEID, #{}),
    Request3 = make_pfcp(session_deletion_request, SEID, #{}),

    ?match({ok, _}, gen_server:call(Pid, Request1)),
    validate_tunnel(LeftIntf,  LeftTEI,  LeftPeerIP,  LeftPeerTEI),
    validate_tunnel(RightIntf, RightTEI, RightPeerIP, RightPeerTEI),

    ?match({error,not_found}, gen_server:call(Pid, Request2)),
    validate_tunnel(LeftIntf,  LeftTEI,  LeftPeerIP,  LeftPeerTEI),
    validate_tunnel(RightIntf, RightTEI, RightPeerIP, RightPeerTEI),

    ?match(#pfcp{ie = #{pfcp_cause := #pfcp_cause{cause = 'Request accepted'}}},
	   gen_server:call(Pid, Request3)),

    %% gtp_u_edp:all/0 bypasses the reg server
    ok = meck:wait(gtp_u_edp_forwarder, terminate, '_', ?TIMEOUT),
    ok = meck:wait(5, gtp_u_edp, handle_info, [{'DOWN', '_', '_', '_', normal}, '_'], ?TIMEOUT),
    ?equal([], gtp_u_edp:all()),

    meck_validate(Config),
    ok.

session_modification_request() ->
    [{doc, "CP to DP Session Modification Request"}].
session_modification_request(Config) ->
    SEID = get_next_teid(),
    InvalidSEID = get_next_teid(),
    LeftIntf = 'grx',
    LeftTEI = get_next_teid(),
    LeftPeerIP = ?CLIENT_IP,
    LeftPeerTEI = get_next_teid(),
    RightIntf = 'proxy-grx',
    RightTEI = get_next_teid(),
    RightPeerIP = ?FINAL_GSN,
    RightPeerTEI = get_next_teid(),

    UpdLeftTEI = get_next_teid(),
    UpdLeftPeerIP = ?CLIENT_IP,
    UpdLeftPeerTEI = get_next_teid(),

    UpdRightTEI = get_next_teid(),
    UpdRightPeerIP = ?FINAL_GSN,
    UpdRightPeerTEI = get_next_teid(),

    {ok, Pid, ?TEST_GSN} = gen_server:call('gtp-u', {bind, LeftIntf}),
    ok = gen_server:call(Pid, clear),

    S = make_gtp_socket(Config),

    Request1 = make_forward_session(
		 SEID,
		 LeftIntf,  LeftTEI,  LeftPeerIP,  LeftPeerTEI,
		 RightIntf, RightTEI, RightPeerIP, RightPeerTEI),

    ?match({ok, _}, gen_server:call(Pid, Request1)),
    validate_tunnel(LeftIntf,  LeftTEI,  LeftPeerIP,  LeftPeerTEI),
    validate_tunnel(RightIntf, RightTEI, RightPeerIP, RightPeerTEI),

    Request2 = make_update_far(
		 InvalidSEID, 1,
		 'Access', LeftIntf, UpdLeftPeerIP, UpdLeftPeerTEI),

    ?match({error,not_found}, gen_server:call(Pid, Request2)),
    validate_tunnel(LeftIntf,  LeftTEI,  LeftPeerIP,  LeftPeerTEI),
    validate_tunnel(RightIntf, RightTEI, RightPeerIP, RightPeerTEI),

    Request3 = make_update_far(
		 SEID, 1,
		 'Access', LeftIntf, UpdLeftPeerIP, UpdLeftPeerTEI),

    ?match(#pfcp{ie = #{pfcp_cause := #pfcp_cause{cause = 'Request accepted'}}},
	   gen_server:call(Pid, Request3)),
    validate_tunnel(LeftIntf, LeftTEI, UpdLeftPeerIP, UpdLeftPeerTEI),
    validate_tunnel(RightIntf, RightTEI, RightPeerIP, RightPeerTEI),

    Request4 = make_update_far(
		 SEID, 2,
		 'Core', RightIntf, UpdRightPeerIP, UpdRightPeerTEI),

    ?match(#pfcp{ie = #{pfcp_cause := #pfcp_cause{cause = 'Request accepted'}}},
	   gen_server:call(Pid, Request4)),
    validate_tunnel(LeftIntf,  LeftTEI,  UpdLeftPeerIP,  UpdLeftPeerTEI),
    validate_tunnel(RightIntf, RightTEI, UpdRightPeerIP, UpdRightPeerTEI),

    Request5 = make_update_pdr(SEID, 1, 'Access', LeftIntf, UpdLeftTEI),

    ?match(#pfcp{ie = #{pfcp_cause := #pfcp_cause{cause = 'Request accepted'}}},
	   gen_server:call(Pid, Request5)),
    validate_tunnel(LeftIntf, UpdLeftTEI, UpdLeftPeerIP, UpdLeftPeerTEI),
    validate_tunnel(RightIntf, RightTEI, UpdRightPeerIP, UpdRightPeerTEI),

    Request6 = make_update_pdr(SEID, 2, 'Core', RightIntf, UpdRightTEI),

    ?match(#pfcp{ie = #{pfcp_cause := #pfcp_cause{cause = 'Request accepted'}}},
	   gen_server:call(Pid, Request6)),
    validate_tunnel(LeftIntf, UpdLeftTEI, UpdLeftPeerIP, UpdLeftPeerTEI),
    validate_tunnel(RightIntf, UpdRightTEI, UpdRightPeerIP, UpdRightPeerTEI),

    %% make sure we did not get an End Marker
    ?equal({error,timeout}, gen_udp:recv(S, 4096, ?TIMEOUT)),

    Request7 = make_update_far(
		 SEID, 1,
		 'Access', LeftIntf, LeftPeerIP, LeftPeerTEI, true),

    ?match(#pfcp{ie = #{pfcp_cause := #pfcp_cause{cause = 'Request accepted'}}},
	   gen_server:call(Pid, Request7)),
    validate_tunnel(LeftIntf,  UpdLeftTEI, LeftPeerIP, LeftPeerTEI),
    validate_tunnel(RightIntf, UpdRightTEI, UpdRightPeerIP, UpdRightPeerTEI),

    %% make sure we DID get an End Marker
    ?match(#gtp{type = end_marker, tei = UpdLeftPeerTEI}, recv_pdu(S, ?TIMEOUT)),

    Request8 = make_pfcp(session_deletion_request, SEID, #{}),
    ?match(#pfcp{ie = #{pfcp_cause := #pfcp_cause{cause = 'Request accepted'}}},
	   gen_server:call(Pid, Request8)),

    gen_udp:close(S),

    %% gtp_u_edp:all/0 bypasses the reg server
    ok = meck:wait(gtp_u_edp_forwarder, terminate, '_', ?TIMEOUT),
    %% wait for 5 monitors, one for each TEI and one for the SEID
    ok = meck:wait(5, gtp_u_edp, handle_info, [{'DOWN', '_', '_', '_', normal}, '_'], ?TIMEOUT),
    ?equal([], gtp_u_edp:all()),

    meck_validate(Config),
    ok.

forward_data() ->
    [{doc, "Test forwarding data works"}].
forward_data(Config) ->
    SEID = get_next_teid(),
    LeftIntf = 'grx',
    LeftTEI = get_next_teid(),
    LeftPeerIP = ?CLIENT_IP,
    LeftPeerTEI = get_next_teid(),
    RightIntf = 'proxy-grx',
    RightTEI = get_next_teid(),
    RightPeerIP = ?FINAL_GSN,
    RightPeerTEI = get_next_teid(),

    {ok, Pid, ?TEST_GSN} = gen_server:call('gtp-u', {bind, LeftIntf}),
    ok = gen_server:call(Pid, clear),

    Request1 = make_forward_session(
		 SEID,
		 LeftIntf,  LeftTEI,  LeftPeerIP,  LeftPeerTEI,
		 RightIntf, RightTEI, RightPeerIP, RightPeerTEI),
    Request2 = make_pfcp(session_deletion_request, SEID, #{}),

    ?match({ok, _}, gen_server:call(Pid, Request1)),
    validate_tunnel(LeftIntf,  LeftTEI,  LeftPeerIP,  LeftPeerTEI),
    validate_tunnel(RightIntf, RightTEI, RightPeerIP, RightPeerTEI),

    EchoFun =
	fun(Socket) ->
		Msg = recv_pdu(Socket, ?PROXY_GSN, ?TIMEOUT),
		?match(#gtp{type = g_pdu, tei = RightPeerTEI}, Msg),
		send_pdu(Socket, ?PROXY_GSN, Msg#gtp{tei = RightTEI}),
		done
	end,
    {ok, EchoPid} = proc_lib:start_link(?MODULE, remote_server, [Config, self(), EchoFun]),

    S = make_gtp_socket(Config),

    Msg = #gtp{version = v1, type = g_pdu, tei = LeftTEI, ie = <<"TESTDATA">>},
    ?match(#gtp{type = g_pdu, tei = LeftPeerTEI}, send_recv_pdu(S, Msg)),

    receive
	{EchoPid, done} -> ok
    after ?TIMEOUT ->
	    ct:fail(timeout)
    end,

    ?match(#pfcp{type = session_deletion_response,
		 ie = #{
		   pfcp_cause := #pfcp_cause{cause = 'Request accepted'},
		   usage_report_sdr :=
		       #usage_report_sdr{
			  group =
			      #{urr_id := #urr_id{id = 1},
				volume_measurement :=
				    #volume_measurement{
				       total = 16, uplink = 8, downlink = 8},
				tp_packet_measurement :=
				    #tp_packet_measurement{
				       total = 2, uplink = 1, downlink = 1}
			       }
			 }
		  }
		},
	   gen_server:call(Pid, Request2)),

    %% gtp_u_edp:all/0 bypasses the reg server
    ok = meck:wait(gtp_u_edp_forwarder, terminate, '_', ?TIMEOUT),
    ok = meck:wait(5, gtp_u_edp, handle_info, [{'DOWN', '_', '_', '_', normal}, '_'], ?TIMEOUT),
    ?equal([], gtp_u_edp:all()),

    meck_validate(Config),
    ok.

query_usage_report() ->
    [{doc, "Test Session Modification with Query URR"}].
query_usage_report(Config) ->
    SEID = get_next_teid(),
    LeftIntf = 'grx',
    LeftTEI = get_next_teid(),
    LeftPeerIP = ?CLIENT_IP,
    LeftPeerTEI = get_next_teid(),
    RightIntf = 'proxy-grx',
    RightTEI = get_next_teid(),
    RightPeerIP = ?FINAL_GSN,
    RightPeerTEI = get_next_teid(),

    {ok, Pid, ?TEST_GSN} = gen_server:call('gtp-u', {bind, LeftIntf}),
    ok = gen_server:call(Pid, clear),

    Request1 = make_forward_session(
		 SEID,
		 LeftIntf,  LeftTEI,  LeftPeerIP,  LeftPeerTEI,
		 RightIntf, RightTEI, RightPeerIP, RightPeerTEI),
    Req2IEs = [#query_urr{group = [#urr_id{id = 1}]},
	       #query_urr{group = [#urr_id{id = 2}]}],
    Request2 = make_pfcp(session_modification_request, SEID, Req2IEs),
    Request3 = make_pfcp(session_deletion_request, SEID, #{}),

    ?match({ok, _}, gen_server:call(Pid, Request1)),
    validate_tunnel(LeftIntf,  LeftTEI,  LeftPeerIP,  LeftPeerTEI),
    validate_tunnel(RightIntf, RightTEI, RightPeerIP, RightPeerTEI),

    EchoFun =
	fun(Socket) ->
		Msg = recv_pdu(Socket, ?PROXY_GSN, ?TIMEOUT),
		?match(#gtp{type = g_pdu, tei = RightPeerTEI}, Msg),
		send_pdu(Socket, ?PROXY_GSN, Msg#gtp{tei = RightTEI}),
		done
	end,
    {ok, EchoPid} = proc_lib:start_link(?MODULE, remote_server, [Config, self(), EchoFun]),

    S = make_gtp_socket(Config),

    Msg = #gtp{version = v1, type = g_pdu, tei = LeftTEI, ie = <<"TESTDATA">>},
    ?match(#gtp{type = g_pdu, tei = LeftPeerTEI}, send_recv_pdu(S, Msg)),

    receive
	{EchoPid, done} -> ok
    after ?TIMEOUT ->
	    ct:fail(timeout)
    end,

    ?match(#pfcp{type = session_modification_response,
		 ie = #{
		   pfcp_cause := #pfcp_cause{cause = 'Request accepted'},
		   usage_report_smr :=
		       #usage_report_smr{
			  group =
			      #{urr_id := #urr_id{id = 1},
				volume_measurement :=
				    #volume_measurement{
				       total = 16, uplink = 8, downlink = 8},
				tp_packet_measurement :=
				    #tp_packet_measurement{
				       total = 2, uplink = 1, downlink = 1}
			       }
			 }
		  }
		},
	   gen_server:call(Pid, Request2)),

    ?match(#pfcp{ie = #{pfcp_cause := #pfcp_cause{cause = 'Request accepted'}}},
	   gen_server:call(Pid, Request3)),

    %% gtp_u_edp:all/0 bypasses the reg server
    ok = meck:wait(gtp_u_edp_forwarder, terminate, '_', ?TIMEOUT),
    ok = meck:wait(5, gtp_u_edp, handle_info, [{'DOWN', '_', '_', '_', normal}, '_'], ?TIMEOUT),
    ?equal([], gtp_u_edp:all()),

    meck_validate(Config),
    ok.

error_indication() ->
    [{doc, "Test that a Error Indication"}].
error_indication(Config) ->
    SEID = get_next_teid(),
    LeftIntf = 'grx',
    InvalidLeftTEI = get_next_teid(),
    LeftTEI = get_next_teid(),
    LeftPeerIP = ?CLIENT_IP,
    LeftPeerTEI = get_next_teid(),
    RightIntf = 'proxy-grx',
    RightTEI = get_next_teid(),
    RightPeerIP = ?FINAL_GSN,
    RightPeerTEI = get_next_teid(),

    {ok, Pid, ?TEST_GSN} = gen_server:call('gtp-u', {bind, LeftIntf}),
    ok = gen_server:call(Pid, clear),

    Request1 = make_forward_session(
		 SEID,
		 LeftIntf,  LeftTEI,  LeftPeerIP,  LeftPeerTEI,
		 RightIntf, RightTEI, RightPeerIP, RightPeerTEI),
    Request2 = make_pfcp(session_deletion_request, SEID, #{}),

    ?match({ok, _}, gen_server:call(Pid, Request1)),
    validate_tunnel(LeftIntf,  LeftTEI,  LeftPeerIP,  LeftPeerTEI),
    validate_tunnel(RightIntf, RightTEI, RightPeerIP, RightPeerTEI),

    S = make_gtp_socket(Config),

    Msg1 = #gtp{version = v1, type = g_pdu, tei = InvalidLeftTEI, ie = <<"TESTDATA">>},
    ?match(#gtp{version = v1, type = error_indication,
		tei = 0, seq_no = undefined,
		ie = #{?'Tunnel Endpoint Identifier Data I' :=
			   #tunnel_endpoint_identifier_data_i{tei = InvalidLeftTEI}}},
	   send_recv_pdu(S, Msg1)),

    Msg2IE = [#tunnel_endpoint_identifier_data_i{tei = LeftPeerTEI}],
    Msg2 = #gtp{version = v1, type = error_indication, tei = 0,
		seq_no = undefined, ie = Msg2IE},
    send_pdu(S, Msg2),

    ClientIP = ip2bin(?CLIENT_IP),
    receive
	#pfcp{version = v1, type = session_report_request, seid = SEID, ie = IEs2} ->
	    ?match(#{report_type := #report_type{erir = 1},
		     error_indication_report :=
			 #error_indication_report{
			    group = #{
			      f_teid :=
				  #f_teid{ipv4 = ClientIP, teid = LeftPeerTEI}
			     }
			   }
		    }, IEs2)
    after ?TIMEOUT ->
	    ct:fail(timeout)
    end,

    EchoFun =
	fun(Socket) ->
		Msg = recv_pdu(Socket, ?PROXY_GSN, ?TIMEOUT),
		?match(#gtp{type = g_pdu, tei = RightPeerTEI}, Msg),

		RespIE = [#tunnel_endpoint_identifier_data_i{tei = RightPeerTEI}],
		Resp = #gtp{version = v1, type = error_indication, tei = 0,
			    seq_no = undefined, ie = RespIE},
		send_pdu(Socket, ?PROXY_GSN, Resp),
		done
	end,
    {ok, EchoPid} = proc_lib:start_link(?MODULE, remote_server, [Config, self(), EchoFun]),

    Msg3 = #gtp{version = v1, type = g_pdu, tei = LeftTEI, ie = <<"TESTDATA">>},
    send_pdu(S, Msg3),

    receive
	{EchoPid, done} -> ok
    after ?TIMEOUT ->
	    ct:fail(timeout)
    end,

    FinalGSN = ip2bin(?FINAL_GSN),
    receive
	#pfcp{version = v1, type = session_report_request, seid = SEID, ie = IEs3} ->
	    ?match(#{report_type := #report_type{erir = 1},
		     error_indication_report :=
			 #error_indication_report{
			    group = #{
			      f_teid :=
				  #f_teid{ipv4 = FinalGSN, teid = RightPeerTEI}
			     }
			   }
		    }, IEs3)
    after ?TIMEOUT ->
	    ct:fail(timeout)
    end,

    Msg4IE = [#tunnel_endpoint_identifier_data_i{tei = InvalidLeftTEI}],
    Msg4 = #gtp{version = v1, type = error_indication, tei = 0,
		seq_no = undefined, ie = Msg4IE},
    send_pdu(S, Msg4),

    receive
	Any -> ct:fail(Any)
    after 500 ->
	    ok
    end,

    ?match(#pfcp{ie = #{pfcp_cause := #pfcp_cause{cause = 'Request accepted'}}},
	   gen_server:call(Pid, Request2)),

    %% gtp_u_edp:all/0 bypasses the reg server
    ok = meck:wait(gtp_u_edp_forwarder, terminate, '_', ?TIMEOUT),
    ok = meck:wait(5, gtp_u_edp, handle_info, [{'DOWN', '_', '_', '_', normal}, '_'], ?TIMEOUT),
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

make_gtp_socket(Config, IP) ->
    make_gtp_socket(Config, IP, ?GTP1u_PORT).

make_gtp_socket(_Config, IP, Port) ->
    {ok, S} = gen_udp:open(Port, [{ip, IP}, {active, false},
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
    ?match({Pid, _} when is_pid(Pid), gtp_u_edp:lookup({Name, LocalTEI})),
    ?match({Pid, _} when is_pid(Pid), gtp_u_edp:lookup({Name, {remote, RemoteIP, RemoteTEI}})),
    ok.

ip2bin(IP) when is_binary(IP) ->
    IP;
ip2bin({A, B, C, D}) ->
    <<A, B, C, D>>;
ip2bin({A, B, C, D, E, F, G, H}) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>.

network_instance(Name) when is_atom(Name) ->
    #network_instance{instance = [atom_to_binary(Name, latin1)]}.

make_pfcp(Type, SEID, IEs) ->
    PFCP = #pfcp{version = v1, type = Type, seid = SEID, seq_no = 0, ie = IEs},
    pfcp_packet:encode(PFCP),
    pfcp_packet:to_map(PFCP).

make_forward_session(SEID,
		     LeftIntf,  LeftTEI,  LeftPeerIP,  LeftPeerTEI,
		     RightIntf, RightTEI, RightPeerIP, RightPeerTEI) ->
    IEs =
	[#f_seid{seid = SEID},
	 #create_pdr{
	    group =
		[#pdr_id{id = 1},
		 #precedence{precedence = 100},
		 #pdi{
		    group =
			[#source_interface{interface = 'Access'},
			 network_instance(LeftIntf),
			 #f_teid{teid = LeftTEI}]
		   },
		 #outer_header_removal{header = 'GTP-U/UDP/IPv4'},
		 #far_id{id = 2},
		 #urr_id{id = 1}]
	   },
	 #create_pdr{
	    group =
		[#pdr_id{id = 2},
		 #precedence{precedence = 100},
		 #pdi{
		    group =
			[#source_interface{interface = 'Core'},
			 network_instance(RightIntf),
			 #f_teid{teid = RightTEI}]
		   },
		 #outer_header_removal{header = 'GTP-U/UDP/IPv4'},
		 #far_id{id = 1},
		 #urr_id{id = 1}]
	   },
	 #create_far{
	    group =
		[#far_id{id = 1},
		 #apply_action{forw = 1},
		 #forwarding_parameters{
		    group =
			[#destination_interface{interface = 'Access'},
			  network_instance(LeftIntf),
			 #outer_header_creation{
			    type = 'GTP-U/UDP/IPv4',
			    teid = LeftPeerTEI,
			    address = ip2bin(LeftPeerIP)
			   }
			]
		   }
		]
	   },
	 #create_far{
	    group =
		[#far_id{id = 2},
		 #apply_action{forw = 1},
		 #forwarding_parameters{
		    group =
			[#destination_interface{interface = 'Core'},
			  network_instance(RightIntf),
			 #outer_header_creation{
			    type = 'GTP-U/UDP/IPv4',
			    teid = RightPeerTEI,
			    address = ip2bin(RightPeerIP)
			   }
			]
		   }
		]
	   },
	 #create_urr{
	    group =
		[#urr_id{id = 1},
		 #measurement_method{volum = 1}
		]
	   }
	],
    make_pfcp(session_establishment_request, 0, IEs).

make_update_pdr(SEID, RuleId, IntfType, Instance, TEI) ->
    IEs =
	[#f_seid{seid = SEID},
	 #update_pdr{
	     group =
		 [#pdr_id{id = RuleId},
		  #precedence{precedence = 100},
		  #pdi{
		     group =
			 [#source_interface{interface = IntfType},
			  network_instance(Instance),
			  #f_teid{teid = TEI}]
		    },
		  #outer_header_removal{header = 'GTP-U/UDP/IPv4'},
		  #far_id{id = RuleId},
		  #urr_id{id = 1}]
	   }
	],
    make_pfcp(session_modification_request, SEID, IEs).

make_update_far(SEID, RuleId, IntfType, Instance, PeerIP, PeerTEI) ->
    make_update_far(SEID, RuleId, IntfType, Instance, PeerIP, PeerTEI, false).

make_update_far(SEID, RuleId, IntfType, Instance, PeerIP, PeerTEI, SndEM) ->
    IEs =
	[#f_seid{seid = SEID},
	 #update_far{
	    group =
		[#far_id{id = RuleId},
		 #apply_action{forw = 1},
		 #update_forwarding_parameters{
		    group =
			[#destination_interface{interface = IntfType},
			 network_instance(Instance),
			 #outer_header_creation{
			    type = 'GTP-U/UDP/IPv4',
			    teid = PeerTEI,
			    address = ip2bin(PeerIP)
			   }
			 | [#sxsmreq_flags{sndem = 1} || SndEM =:= true]
			]
		   }
		]
	   }
	],
    make_pfcp(session_modification_request, SEID, IEs).
