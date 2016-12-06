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
	 send/3, bind/2]).

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

start_link({Name, SocketOpts}) ->
    RegName = port_reg_name(Name),
    lager:info("RegName: ~p", [RegName]),
    gen_server:start_link({local, RegName}, ?MODULE, [Name, SocketOpts], []).

port_reg_name(Name) when is_atom(Name) ->
    BinName = iolist_to_binary(io_lib:format("port_~s", [Name])),
    binary_to_atom(BinName, latin1).

send(Pid, IP, Data) ->
    gen_server:cast(Pid, {send, IP, Data}).

bind(Name, Owner) ->
    lager:info("RegName: ~p", [port_reg_name(Name)]),
    case erlang:whereis(port_reg_name(Name)) of
	Pid when is_pid(Pid) ->
	    gen_server:call(Pid, {bind, Owner});
	_ ->
	    {reply, {error, not_found}}
    end.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([Name, SocketOpts]) ->
    %% TODO: better config validation and handling
    IP    = proplists:get_value(ip, SocketOpts),
    NetNs = proplists:get_value(netns, SocketOpts),

    {ok, Recv} = make_gtp_socket(NetNs, IP, ?GTP1u_PORT, SocketOpts),
    {ok, Send} = make_gtp_socket(NetNs, IP, 0, SocketOpts),

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

handle_call({delete_pdp_context, _PeerIP, LocalTEI, _RemoteTEI, _Args} = _Request,
	    _From, #state{name = Name} = State) ->

    lager:info("EDP Port Delete PDP Context Call ~p: ~p", [_From, _Request]),
    Reply =
	case gtp_u_edp:lookup({Name, LocalTEI}) of
	    Pid when is_pid(Pid) ->
		gtp_u_edp_handler:del_tunnel(Pid);
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

handle_cast({send, IP, Data}, #state{send = Send} = State) ->
    R = gen_socket:sendto(Send, {inet4, IP, ?GTP1u_PORT}, Data),
    lager:debug("Send Result: ~p", [R]),
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
make_gtp_socket(NetNs, {_,_,_,_} = IP, Port, Opts) when is_list(NetNs) ->
    {ok, Socket} = gen_socket:socketat(NetNs, inet, dgram, udp),
    bind_gtp_socket(Socket, IP, Port, Opts);
make_gtp_socket(_NetNs, {_,_,_,_} = IP, Port, Opts) ->
    {ok, Socket} = gen_socket:socket(inet, dgram, udp),
    bind_gtp_socket(Socket, IP, Port, Opts).

bind_gtp_socket(Socket, {_,_,_,_} = IP, Port, Opts) ->
    case proplists:get_bool(freebind, Opts) of
	true ->
	    ok = gen_socket:setsockopt(Socket, sol_ip, freebind, true);
	_ ->
	    ok
    end,
    ok = gen_socket:bind(Socket, {inet4, IP, Port}),
    ok = gen_socket:setsockopt(Socket, sol_ip, recverr, true),
    ok = gen_socket:input_event(Socket, true),
    lists:foreach(socket_setopts(Socket, _), Opts),
    {ok, Socket}.

socket_setopts(Socket, {netdev, Device})
  when is_list(Device); is_binary(Device) ->
    BinDev = iolist_to_binary([Device, 0]),
    ok = gen_socket:setsockopt(Socket, sol_socket, bindtodevice, BinDev);
socket_setopts(_Socket, _) ->
    ok.

handle_input(Socket, State) ->
    case gen_socket:recvfrom(Socket) of
	{error, _} ->
	    handle_err_input(Socket, State);

	{ok, {inet4, IP, Port}, Data} ->
	    ok = gen_socket:input_event(Socket, true),
	    handle_msg(Socket, IP, Port, Data, State);

	Other ->
	    lager:error("got unhandled input: ~p", [Other]),
	    ok = gen_socket:input_event(Socket, true),
	    {noreply, State}
    end.

handle_err_input(Socket, State) ->
    case gen_socket:recvmsg(Socket, ?MSG_DONTWAIT bor ?MSG_ERRQUEUE) of
	Other ->
	    lager:error("got unhandled error input: ~p", [Other]),
	    ok = gen_socket:input_event(Socket, true),
	    {noreply, State}
    end.

handle_msg(Socket, IP, Port, Data, State) ->
    try gtp_packet:decode(Data) of
	Msg = #gtp{version = v1} ->
	    lager:debug("Msg: ~p", [lager:pr(Msg, ?MODULE)]),
	    handle_msg_1(Socket, IP, Port, Msg, State);

	Other ->
	    lager:debug("Msg: ~p", [Other]),
	    {noreply, State}
    catch
	Class:Error ->
	    lager:debug("Info Error: ~p:~p", [Class, Error]),
	    {noreply, State}
    end.

handle_msg_1(Socket, IP, Port,
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
    R = gen_socket:sendto(Socket, {inet4, IP, Port}, Data),
    lager:debug("Echo Reply Send Result: ~p", [R]),

    {noreply, State};

handle_msg_1(Socket, IP, Port,
	     #gtp{version = v1} = Msg,
	     #state{name = Name} = State) ->
    gtp_u_edp_handler:handle_msg(Name, Socket, IP, Port, Msg),
    {noreply, State};

handle_msg_1(_Socket, _IP, _Port, _Msg, State) ->
    {noreply, State}.

clear_port(Pid) ->
    gen_server:cast(Pid, stop),
    ok.
