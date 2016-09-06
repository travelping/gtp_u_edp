%% Copyright 2016, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(gtp_u_edp_handler).

%% API
-export([start_link/6, add_tunnel/5, del_tunnel/1, handle_msg/4]).

-include_lib("gtplib/include/gtp_packet.hrl").

%% ===================================================================
%% API functions
%% ===================================================================

start_link(Port, PeerIP, LocalTEI, RemoteTEI, HandlerMod, HandlerArgs) ->
    HandlerMod:start_link(Port, PeerIP, LocalTEI, RemoteTEI, HandlerArgs).

add_tunnel(Port, PeerIP, LocalTEI, RemoteTEI, {Handler, HandlerArgs}) ->
    HandlerMod = map_handler(Handler),
    gtp_u_edp_handler_sup:add_tunnel(Port, PeerIP, LocalTEI, RemoteTEI, HandlerMod, HandlerArgs).

del_tunnel(Pid) ->
    gen_server:cast(Pid, del_tunnel).

handle_msg(Name, IP, Port, #gtp{tei = TEI} = Msg) ->
    case gtp_u_edp:lookup({Name, TEI}) of
	Handler when is_pid(Handler) ->
	    gen_server:cast(Handler, {handle_msg, Name, IP, Port, Msg});
	_ ->
	    ok
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

map_handler(forward) ->
    gtp_u_edp_forwarder.
