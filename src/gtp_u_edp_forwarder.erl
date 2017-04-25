%% Copyright 2016, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(gtp_u_edp_forwarder).

-behaviour(gen_server).

%% API
-export([start_link/6]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-include_lib("gtplib/include/gtp_packet.hrl").

-define(SERVER, ?MODULE).
-define('Tunnel Endpoint Identifier Data I',	{tunnel_endpoint_identifier_data_i, 0}).

-record(port, {name, pid, ip, local_tei, remote_tei}).
-record(state, {owner, grx_port, proxy_port}).

%%%===================================================================
%%% API
%%%===================================================================

start_link(Port, PeerIP, LocalTEI, RemoteTEI, Owner, Args) ->
    gen_server:start_link(?MODULE, [Port, PeerIP, LocalTEI, RemoteTEI, Owner | Args], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([PortName, PeerIP, LocalTEI, RemoteTEI, Owner,
      ProxyPortName, ProxyPeerIP, ProxyLocalTEI, ProxyRemoteTEI]) ->
    try
	GrxPort = init_port(PortName, PeerIP, LocalTEI, RemoteTEI),
	ProxyPort = init_port(ProxyPortName, ProxyPeerIP, ProxyLocalTEI, ProxyRemoteTEI),

	State = #state{owner = Owner, grx_port = GrxPort, proxy_port = ProxyPort},
	{ok, State}
    catch
	error:noproc ->
	    {stop, {error, invalid_port}}
    end.

handle_call([update_tunnel, PortName, PeerIP, LocalTEI, RemoteTEI,
	     ProxyPortName, ProxyPeerIP, ProxyLocalTEI, ProxyRemoteTEI],
	    _From, #state{grx_port = GrxPort0,
			  proxy_port = ProxyPort0} = State0) ->

    try
	GrxPort = update_port(GrxPort0, PortName, PeerIP, LocalTEI, RemoteTEI),
	ProxyPort = update_port(ProxyPort0, ProxyPortName, ProxyPeerIP,
				ProxyLocalTEI, ProxyRemoteTEI),
	State = State0#state{grx_port = GrxPort, proxy_port = ProxyPort},
	{reply, ok, State}
    catch
	error:noproc ->
	    {stop, normal, {error, invalid_port}, State0};
	throw:Reason ->
	    {stop, normal, Reason, State0}
    end;

handle_call(_Request, _From, State) ->
    lager:warning("invalid CALL: ~p", [_Request]),
    {reply, error, State}.

handle_cast({handle_msg, InPortName, IP, Port,
	     #gtp{type = error_indication,
		  ie = #{?'Tunnel Endpoint Identifier Data I' :=
			     #tunnel_endpoint_identifier_data_i{tei = TEI}}} = Msg},
	    #state{grx_port = #port{name = InPortName, remote_tei = TEI} = GrxPort,
		   proxy_port = ProxyPort} = State) ->
    send_error_indication(ProxyPort),
    packet_in(GrxPort, IP, Port, Msg),
    {noreply, State};

handle_cast({handle_msg, InPortName, IP, Port,
	     #gtp{type = error_indication,
		  ie = #{?'Tunnel Endpoint Identifier Data I' :=
			     #tunnel_endpoint_identifier_data_i{tei = TEI}}} = Msg},
	    #state{grx_port = GrxPort,
		   proxy_port = #port{name = InPortName, remote_tei = TEI} = ProxyPort} = State) ->
    send_error_indication(GrxPort),
    packet_in(ProxyPort, IP, Port, Msg),
    {noreply, State};

handle_cast({handle_msg, InPortName, _IP, _Port, #gtp{tei = TEI} = Msg},
	    #state{grx_port = #port{name = InPortName, local_tei = TEI},
		   proxy_port = ProxyPort} = State) ->
    forward(ProxyPort, Msg),
    {noreply, State};

handle_cast({handle_msg, InPortName, _IP, _Port, #gtp{tei = TEI} = Msg},
	    #state{grx_port = GrxPort,
		   proxy_port = #port{name = InPortName, local_tei = TEI}} = State) ->
    forward(GrxPort, Msg),
    {noreply, State};

handle_cast(del_tunnel, State) ->
    lager:debug("Forwarder: delete tunnel"),
    {stop, normal, State};

handle_cast(stop, State) ->
    lager:debug("Forwarder: STOP"),
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
    gtp_u_edp:register(Name, {remote, IP, RemoteTEI}),

    #port{name = Name, pid = Pid, ip = IP,
	  local_tei  = LocalTEI,
	  remote_tei = RemoteTEI}.

update_tei_registration(Name, Old, New)
  when Old /= New ->
    gtp_u_edp:register(Name, New),
    gtp_u_edp:unregister(Name, Old);
update_tei_registration(_Name, _Old, _New) ->
    ok.

update_port(#port{name = Name} = Port,
	    Name, IP, LocalTEI, RemoteTEI) ->
    update_tei_registration(Name, Port#port.local_tei, LocalTEI),
    update_tei_registration(Name, {remote, Port#port.ip, Port#port.remote_tei},
			          {remote, IP, RemoteTEI}),
    Port#port{ip = IP, local_tei  = LocalTEI, remote_tei = RemoteTEI}.

forward(#port{pid = Pid, remote_tei = TEI, ip = IP}, Msg) ->
    Data = gtp_packet:encode(Msg#gtp{tei = TEI}),
    gtp_u_edp_port:send(Pid, IP, Data).

send_error_indication(#port{pid = Pid, local_tei = TEI, ip = IP}) ->
    gtp_u_edp_port:send_error_indication(Pid, IP, TEI).

packet_in(#port{pid = Pid}, IP, Port, Msg) ->
    gtp_u_edp_port:packet_in(Pid, IP, Port, Msg).
