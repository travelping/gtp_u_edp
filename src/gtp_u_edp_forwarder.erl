%% Copyright 2016, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(gtp_u_edp_forwarder).

-behaviour(gen_server).

%% API
-export([start_link/5]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-include_lib("gtplib/include/gtp_packet.hrl").

-define(SERVER, ?MODULE).

-record(port, {name, pid, ip, local_tei, remote_tei}).
-record(state, {grx_port, proxy_port}).

%%%===================================================================
%%% API
%%%===================================================================

start_link(Port, PeerIP, LocalTEI, RemoteTEI, Args) ->
    gen_server:start_link(?MODULE, [Port, PeerIP, LocalTEI, RemoteTEI | Args], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([PortName, PeerIP, LocalTEI, RemoteTEI,
      ProxyPortName, ProxyPeerIP, ProxyLocalTEI, ProxyRemoteTEI]) ->
    try
	GrxPort = init_port(PortName, PeerIP, LocalTEI, RemoteTEI),
	ProxyPort = init_port(ProxyPortName, ProxyPeerIP, ProxyLocalTEI, ProxyRemoteTEI),

	State = #state{grx_port = GrxPort, proxy_port = ProxyPort},
	{ok, State}
    catch
	error:noproc ->
	    {stop, {error, invalid_port}}
    end.

handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_cast({handle_msg, InPortName, _IP, _Port, Msg},
	    #state{grx_port = #port{name = InPortName},
		   proxy_port = ProxyPort} = State) ->
    forward(ProxyPort, Msg),
    {noreply, State};

handle_cast({handle_msg, InPortName, _IP, _Port, Msg},
	    #state{grx_port = GrxPort,
		   proxy_port = #port{name = InPortName}} = State) ->
    forward(GrxPort, Msg),
    {noreply, State};

handle_cast(del_tunnel, State) ->
    lager:debug("Forwarder: delete tunnel"),
    {stop, normal, State};

handle_cast(Msg, State) ->
    lager:debug("Forwarder: unexpected Msg: ~p", [Msg]),
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

get_port_pid(Name) ->
    RegName = gtp_u_edp_port:port_reg_name(Name),
    whereis(RegName).

init_port(Name, IP, LocalTEI, RemoteTEI) ->
    Pid = get_port_pid(Name),
    link(Pid),
    gtp_u_edp:register(Name, LocalTEI),

    #port{name = Name, pid = Pid, ip = IP, local_tei = LocalTEI, remote_tei = RemoteTEI}.

forward(#port{pid = Pid, remote_tei = TEI, ip = IP}, Msg) ->
    Data = gtp_packet:encode(Msg#gtp{tei = TEI}),
    gtp_u_edp_port:send(Pid, IP, Data).
