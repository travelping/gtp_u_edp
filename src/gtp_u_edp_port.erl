%% Copyright 2016, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(gtp_u_edp_port).

%% A GTP-U proxy instance is described by
%%  * GRX IP and sending port
%%  * Proxy IP and sending port
%%
%% It will open the GTPv1-U port (2152) for recieving
%% and open the specified sending ports on the GRP and
%% Proxy IP's

-behaviour(gen_server).

-compile({parse_transform, cut}).

-include_lib("gen_socket/include/gen_socket.hrl").
-include_lib("gtplib/include/gtp_packet.hrl").
-include("include/gtp_u_edp.hrl").

%% API
-export([start_sockets/0, start_link/1, port_reg_name/1,
	 send/4, send_error_indication/4, packet_in/5, bind/2,
	 sendto/4]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {name, ip, owner, recv, send}).

%%%===================================================================
%%% API
%%%===================================================================

start_sockets() ->
    {ok, Sockets} = application:get_env(sockets),
    lists:foreach(fun(Socket) ->
			  gtp_u_edp_port_sup:new(Socket)
		  end, Sockets),
    ok.

start_link({Name, SocketOpts0}) ->
    RegName = port_reg_name(Name),
    lager:info("RegName: ~p", [RegName]),
    SocketOpts = validate_options(SocketOpts0),
    gen_server:start_link({local, RegName}, ?MODULE, [Name, SocketOpts], []).

port_reg_name(Name) when is_atom(Name) ->
    BinName = iolist_to_binary(io_lib:format("port_~s", [Name])),
    binary_to_atom(BinName, latin1).

send(Pid, Req, IP, Data) ->
    gen_server:cast(Pid, {send, Req, IP, Data}).

send_error_indication(Pid, Req, IP, TEI)
  when is_pid(Pid) ->
    gen_server:cast(Pid, {send_error_indication, Req, IP, TEI});

send_error_indication(Socket, IP, TEI, ExtHdr) ->
    {_, LocalIP, _} = gen_socket:getsockname(Socket),
    ResponseIEs = [#tunnel_endpoint_identifier_data_i{tei = TEI},
		   #gsn_address{address = ip2bin(LocalIP)}],
    Response = #gtp{version = v1, type = error_indication, tei = 0,
		    seq_no = undefined, ext_hdr = ExtHdr, ie = ResponseIEs},
    Data = gtp_packet:encode(Response),
    gtp_u_edp_port:sendto(Socket, IP, ?GTP1u_PORT, Data).

packet_in(Pid, Req, IP, Port, Msg) ->
    gen_server:cast(Pid, {packet_in, Req, IP, Port, Msg}).

bind(Name, Owner) ->
    lager:info("RegName: ~p", [port_reg_name(Name)]),
    case erlang:whereis(port_reg_name(Name)) of
	Pid when is_pid(Pid) ->
	    gen_server:call(Pid, {bind, Owner});
	_ ->
	    {reply, {error, not_found}}
    end.

sendto(Socket, {_,_,_,_} = IP, Port, Data) ->
    gen_socket:sendto(Socket, {inet4, IP, Port}, Data);
sendto(Socket, {_,_,_,_,_,_,_,_} = IP, Port, Data) ->
    gen_socket:sendto(Socket, {inet6, IP, Port}, Data).

%%%===================================================================
%%% Options Validation
%%%===================================================================

-define(SocketDefaults, [{ip, invalid}]).

validate_options(Values0) ->
    Values = proplists:unfold(Values0),
    validate_options(fun validate_option/2, Values, ?SocketDefaults).

validate_options(_Fun, []) ->
        [];
validate_options(Fun, [Opt | Tail]) when is_atom(Opt) ->
        [Fun(Opt, true) | validate_options(Fun, Tail)];
validate_options(Fun, [{Opt, Value} | Tail]) ->
        [{Opt, Fun(Opt, Value)} | validate_options(Fun, Tail)].

validate_options(Fun, Options, Defaults)
  when is_list(Options), is_list(Defaults) ->
    Opts = lists:ukeymerge(1, lists:keysort(1, Options), lists:keysort(1, Defaults)),
    maps:from_list(validate_options(Fun, Opts)).

validate_option(name, Value) when is_atom(Value) ->
    Value;
validate_option(type, 'gtp-u') ->
    'gtp-u';
validate_option(ip, Value)
  when is_tuple(Value) andalso
       (tuple_size(Value) == 4 orelse tuple_size(Value) == 8) ->
    Value;
validate_option(netdev, Value)
  when is_list(Value); is_binary(Value) ->
    Value;
validate_option(netns, Value)
  when is_list(Value); is_binary(Value) ->
    Value;
validate_option(freebind, Value) when is_boolean(Value) ->
    Value;
validate_option(reuseaddr, Value) when is_boolean(Value) ->
    Value;
validate_option(rcvbuf, Value)
  when is_integer(Value) andalso Value > 0 ->
    Value;
validate_option(Opt, Value) ->
    throw({error, {options, {Opt, Value}}}).

%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([Name, #{ip := IP} = SocketOpts]) ->
    process_flag(trap_exit, true),

    {ok, Recv} = make_gtp_socket(IP, ?GTP1u_PORT, SocketOpts),
    {ok, Send} = make_gtp_socket(IP, 0, SocketOpts),

    gtp_u_edp_metrics:init(Name),

    State = #state{name = Name,
		   ip = IP,
		   owner = undefined,
		   recv = Recv,
		   send = Send},
    {ok, State}.

handle_call({bind, Owner}, _From, #state{ip = IP} = State) ->
    lager:info("EDP Bind ~p", [Owner]),
    Reply = {ok, self(), IP},
    {reply, Reply, State#state{owner = Owner}};

handle_call({create_pdp_context, PeerIP, LocalTEI, RemoteTEI, Args} = _Request,
	    {Owner, _Tag} = _From, #state{name = Name} = State) ->

    lager:info("EDP Port Create PDP Context Call ~p: ~p", [_From, _Request]),
    Reply = gtp_u_edp_handler:add_tunnel(Name, PeerIP, LocalTEI, RemoteTEI, Owner, Args),

    {reply, Reply, State};

handle_call({update_pdp_context, _, LocalTEI, _, _} = Request,
	    _From, #state{name = Name} = State) ->

    lager:info("EDP Port Update PDP Context Call ~p: ~p", [_From, Request]),
    Reply =
	case gtp_u_edp:lookup({Name, LocalTEI}) of
	    Pid when is_pid(Pid) ->
		gen_server:call(Pid, Request);
	    _ ->
		{error, not_found}
	end,
    {reply, Reply, State};

handle_call({delete_pdp_context, _, LocalTEI, _, _} = Request,
	    _From, #state{name = Name} = State) ->

    lager:info("EDP Port Delete PDP Context Call ~p: ~p", [_From, Request]),
    Reply =
	case gtp_u_edp:lookup({Name, LocalTEI}) of
	    Pid when is_pid(Pid) ->
		gen_server:call(Pid, Request);
	    _ ->
		{error, not_found}
	end,
    {reply, Reply, State};

handle_call(clear, _From, #state{name = Name} = State) ->
    Reply = gtp_u_edp:port_foreach(fun clear_port/1, Name),
    {reply, Reply, State};

handle_call(_Request, _From, State) ->
    lager:info("EDP Port Call ~p: ~p", [_From, _Request]),
    Reply = ok,
    {reply, Reply, State}.

handle_cast({send, Req, IP, Data}, #state{send = Send} = State) ->
    case sendto(Send, IP, ?GTP1u_PORT, Data) of
	{ok, _} ->
	    gtp_u_edp_metrics:measure_request(Req),
	    ok;
	Other ->
	    gtp_u_edp_metrics:measure_request_error(Req, send_failed),
	    lager:debug("invalid send result: ~p", [Other])
    end,
    {noreply, State};

handle_cast({send_error_indication, _Req, IP, TEI}, #state{send = Send} = State) ->
    case send_error_indication(Send, IP, TEI, []) of
	{ok, _} ->
	    ok;
	Other ->
	    lager:debug("invalid send result: ~p", [Other])
    end,
    {noreply, State};

handle_cast({packet_in, Req, IP, Port, Msg}, #state{owner = Owner} = State)
  when is_pid(Owner) ->
    Owner ! {packet_in, IP, Port, Msg},
    gtp_u_edp_metrics:measure_request(Req),
    {noreply, State};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({Socket, input_ready}, State) ->
    handle_input(Socket, State);

handle_info(Info, State) ->
    lager:debug("Info: ~p", [Info]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

ip2bin(IP) when is_binary(IP) ->
    IP;
ip2bin({A, B, C, D}) ->
    <<A, B, C, D>>;
ip2bin({A, B, C, D, E, F, G, H}) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>.

family({_,_,_,_}) -> inet;
family({_,_,_,_,_,_,_,_}) -> inet6.

make_gtp_socket(IP, Port, #{netns := NetNs} = Opts)
  when is_list(NetNs) ->
    {ok, Socket} = gen_socket:socketat(NetNs, family(IP), dgram, udp),
    bind_gtp_socket(Socket, IP, Port, Opts);
make_gtp_socket(IP, Port, Opts) ->
    {ok, Socket} = gen_socket:socket(family(IP), dgram, udp),
    bind_gtp_socket(Socket, IP, Port, Opts).

bind_gtp_socket(Socket, {_,_,_,_} = IP, Port, Opts) ->
    ok = socket_ip_freebind(Socket, Opts),
    ok = socket_netdev(Socket, Opts),
    ok = gen_socket:bind(Socket, {inet4, IP, Port}),
    ok = gen_socket:setsockopt(Socket, sol_ip, recverr, true),
    ok = gen_socket:setsockopt(Socket, sol_ip, mtu_discover, 0),
    ok = gen_socket:input_event(Socket, true),
    maps:fold(fun(K, V, ok) -> ok = socket_setopts(Socket, K, V) end, ok, Opts),
    {ok, Socket};
bind_gtp_socket(Socket, {_,_,_,_,_,_,_,_} = IP, Port, Opts) ->
    %% ok = gen_socket:setsockopt(Socket, sol_ip, recverr, true),
    ok = socket_netdev(Socket, Opts),
    ok = gen_socket:bind(Socket, {inet6, IP, Port}),
    maps:fold(fun(K, V, ok) -> ok = socket_setopts(Socket, K, V) end, ok, Opts),
    ok = gen_socket:input_event(Socket, true),
    {ok, Socket}.

socket_ip_freebind(Socket, #{freebind := true}) ->
    gen_socket:setsockopt(Socket, sol_ip, freebind, true);
socket_ip_freebind(_, _) ->
    ok.

socket_netdev(Socket, #{netdev := Device}) ->
    BinDev = iolist_to_binary([Device, 0]),
    gen_socket:setsockopt(Socket, sol_socket, bindtodevice, BinDev);
socket_netdev(_, _) ->
    ok.

socket_setopts(Socket, rcvbuf, Size) when is_integer(Size) ->
    case gen_socket:setsockopt(Socket, sol_socket, rcvbufforce, Size) of
	ok -> ok;
	_  -> gen_socket:setsockopt(Socket, sol_socket, rcvbuf, Size)
    end;
socket_setopts(Socket, reuseaddr, true) ->
    ok = gen_socket:setsockopt(Socket, sol_socket, reuseaddr, true);
socket_setopts(_Socket, _, _) ->
    ok.

handle_input(Socket, State) ->
    case gen_socket:recvfrom(Socket) of
	{error, _} ->
	    handle_err_input(Socket, State);

	{ok, {_, IP, Port}, Data} ->
	    ArrivalTS = erlang:monotonic_time(),
	    ok = gen_socket:input_event(Socket, true),
	    handle_msg(Socket, ArrivalTS, IP, Port, Data, State);

	Other ->
	    lager:error("got unhandled input: ~p", [Other]),
	    ok = gen_socket:input_event(Socket, true),
	    {noreply, State}
    end.

-define(SO_EE_ORIGIN_LOCAL,      1).
-define(SO_EE_ORIGIN_ICMP,       2).
-define(SO_EE_ORIGIN_ICMP6,      3).
-define(SO_EE_ORIGIN_TXSTATUS,   4).
-define(ICMP_DEST_UNREACH,       3).       %% Destination Unreachable
-define(ICMP_HOST_UNREACH,       1).       %% Host Unreachable
-define(ICMP_PROT_UNREACH,       2).       %% Protocol Unreachable
-define(ICMP_PORT_UNREACH,       3).       %% Port Unreachable

handle_socket_error({?SOL_IP, ?IP_RECVERR, {sock_err, _ErrNo, ?SO_EE_ORIGIN_ICMP, ?ICMP_DEST_UNREACH, Code, _Info, _Data}},
		    _IP, _Port, _State)
  when Code == ?ICMP_HOST_UNREACH; Code == ?ICMP_PORT_UNREACH ->
    ok;

handle_socket_error(Error, IP, _Port, _State) ->
    lager:debug("got unhandled error info for ~s: ~p", [inet:ntoa(IP), Error]),
    ok.

handle_err_input(Socket, State) ->
    case gen_socket:recvmsg(Socket, ?MSG_DONTWAIT bor ?MSG_ERRQUEUE) of
	{ok, {inet4, IP, Port}, Error, _Data} ->
	    lists:foreach(handle_socket_error(_, IP, Port, State), Error),
	    ok = gen_socket:input_event(Socket, true),
	    {noreply, State};

	Other ->
	    lager:error("got unhandled error input: ~p", [Other]),
	    ok = gen_socket:input_event(Socket, true),
	    {noreply, State}
    end.

handle_msg(Socket, ArrivalTS, IP, Port, Data, #state{name = Name} = State) ->
    try gtp_packet:decode(Data) of
	Msg = #gtp{version = v1} ->
	    Req = make_request(Name, Msg, ArrivalTS),
	    handle_msg_1(Socket, Req, IP, Port, Msg, State);

	Other ->
	    gtp_u_edp_metrics:measure_request_error(Name, ArrivalTS, invalid_payload),
	    lager:debug("from ~p:~w, ~p", [IP, Port, Other]),
	    {noreply, State}
    catch
	Class:Error ->
	    gtp_u_edp_metrics:measure_request_error(Name, ArrivalTS, invalid_payload),
	    lager:debug("Info Error: ~p:~p", [Class, Error]),
	    {noreply, State}
    end.

handle_msg_1(Socket, Req, IP, Port,
	     #gtp{version = v1, type = echo_request, tei = TEI, seq_no = SeqNo}, State) ->

    lager:debug("Echo Request from ~p:~w, TEI: ~w, SeqNo: ~w", [IP, Port, TEI, SeqNo]),
    %% GTP-u does not use the recovery IE, but it needs to be present
    %%
    %% 3GPP, TS 29.281, Section 7.2.2:
    %%   The Restart Counter value in the Recovery information element shall not be
    %%   used, i.e. it shall be set to zero by the sender and shall be ignored by
    %%   the receiver. The Recovery information element is mandatory due to backwards
    %%   compatibility reasons.
    ResponseIEs = [#recovery{restart_counter = 0}],

    Response = #gtp{version = v1, type = echo_response, tei = TEI, seq_no = SeqNo, ie = ResponseIEs},
    Data = gtp_packet:encode(Response),
    R = sendto(Socket, IP, Port, Data),
    lager:debug("Echo Reply Send Result: ~p", [R]),
    gtp_u_edp_metrics:measure_request(Req),

    {noreply, State};

handle_msg_1(Socket, Req, IP, Port,
	     #gtp{version = v1} = Msg,
	     #state{name = Name} = State) ->
    gtp_u_edp_handler:handle_msg(Name, Socket, Req, IP, Port, Msg),
    {noreply, State};

handle_msg_1(_Socket, _Req, _IP, _Port, _Msg, State) ->
    {noreply, State}.

clear_port(Pid) ->
    gen_server:cast(Pid, stop),
    ok.

make_request(Name, Msg, ArrivalTS) ->
    #request{name = Name, arrival_ts = ArrivalTS, msg = Msg}.
