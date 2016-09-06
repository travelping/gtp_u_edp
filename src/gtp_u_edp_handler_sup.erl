%% Copyright 2016, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(gtp_u_edp_handler_sup).

-behaviour(supervisor).

%% API
-export([start_link/0, add_tunnel/6]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%% ===================================================================
%% API functions
%% ===================================================================

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

add_tunnel(Port, PeerIP, LocalTEI, RemoteTEI, Handler, HandlerOpts) ->
    supervisor:start_child(?SERVER, [Port, PeerIP, LocalTEI, RemoteTEI, Handler, HandlerOpts]).

%% ===================================================================
%% Supervisor callbacks
%% ===================================================================

init([]) ->
    {ok, {{simple_one_for_one, 5, 10},
	  [{gtp_u_edp_handler, {gtp_u_edp_handler, start_link, []}, temporary, 1000, worker, [gtp_u_edp_handler]}]}}.
