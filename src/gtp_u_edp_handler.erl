%% Copyright 2016, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(gtp_u_edp_handler).

%% API
-export([start_link/7, add_tunnel/6, del_tunnel/1, handle_msg/5]).

-include_lib("gtplib/include/gtp_packet.hrl").

-define('Tunnel Endpoint Identifier Data I',	{tunnel_endpoint_identifier_data_i, 0}).
-define('GTP-U Peer Address',			{gsn_address, 0}).

%% ===================================================================
%% API functions
%% ===================================================================

start_link(Port, PeerIP, LocalTEI, RemoteTEI, Owner, HandlerMod, HandlerArgs) ->
    HandlerMod:start_link(Port, PeerIP, LocalTEI, RemoteTEI, Owner, HandlerArgs).

add_tunnel(Port, PeerIP, LocalTEI, RemoteTEI, Owner, {Handler, HandlerArgs}) ->
    HandlerMod = map_handler(Handler),
    gtp_u_edp_handler_sup:add_tunnel(Port, PeerIP, LocalTEI, RemoteTEI, Owner, HandlerMod, HandlerArgs).

del_tunnel(Pid) ->
    gen_server:cast(Pid, del_tunnel).

handle_msg(Name, Socket, IP, Port, #gtp{type = g_pdu, tei = TEI, seq_no = _SeqNo} = Msg)
  when is_integer(TEI), TEI /= 0 ->
    case gtp_u_edp:lookup({Name, TEI}) of
	Handler when is_pid(Handler) ->
	    gen_server:cast(Handler, {handle_msg, Name, IP, Port, Msg});
	_ ->
	    lager:notice("g_pdu from ~p:~w, TEI: ~w, SeqNo: ~w", [IP, Port, TEI, _SeqNo]),

	    ResponseIEs = [#tunnel_endpoint_identifier_data_i{tei = TEI},
			   #gsn_address{address = ip2bin(IP)}],
	    ExtHdr = [{udp_port, Port}],
	    Response = #gtp{version = v1, type = error_indication, tei = 0,
			    seq_no = 0, ext_hdr = ExtHdr, ie = ResponseIEs},
	    Data = gtp_packet:encode(Response),
	    gen_socket:sendto(Socket, {inet4, IP, Port}, Data),
	    ok
    end;
handle_msg(Name, _Socket, IP, Port,
	   #gtp{type = error_indication,
		ie = #{?'Tunnel Endpoint Identifier Data I' :=
			   #tunnel_endpoint_identifier_data_i{tei = TEI}}} = Msg) ->
    lager:notice("error_indication from ~p:~w, TEI: ~w", [IP, Port, TEI]),
    case gtp_u_edp:lookup({Name, {remote, TEI}}) of
	Handler when is_pid(Handler) ->
	    gen_server:cast(Handler, {handle_msg, Name, IP, Port, Msg});
	_ ->
	   ok
   end;
handle_msg(_Name, _Socket, IP, Port, #gtp{type = Type, tei = TEI, seq_no = _SeqNo}) ->
    lager:notice("~p from ~p:~w, TEI: ~w, SeqNo: ~w", [Type, IP, Port, TEI, _SeqNo]),
    ok.

%%%===================================================================
%%% Internal functions
%%%===================================================================

ip2bin(IP) when is_binary(IP) ->
    IP;
ip2bin({A, B, C, D}) ->
    <<A, B, C, D>>;
ip2bin({A, B, C, D, E, F, G, H}) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>.

map_handler(forward) ->
    gtp_u_edp_forwarder.
