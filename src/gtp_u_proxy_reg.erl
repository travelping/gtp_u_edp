%% Copyright 2016, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(gtp_u_proxy_reg).

-behaviour(regine_server).

%% API
-export([start_link/0]).
-export([register/2, lookup/1]).
-export([all/0]).

%% regine_server callbacks
-export([init/1, handle_register/4, handle_unregister/3, handle_pid_remove/3, handle_death/3, terminate/2]).

%% --------------------------------------------------------------------
%% Include files
%% --------------------------------------------------------------------

-define(SERVER, ?MODULE).

-record(state, {}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    regine_server:start_link({local, ?SERVER}, ?MODULE, []).

register(Name, IP) ->
    regine_server:register(?SERVER, self(), Name, IP).

lookup(Key) ->
    case ets:lookup(?SERVER, Key) of
	[{Key, Pid}] ->
	    Pid;
	_ ->
	    undefined
    end.

all() ->
    ets:tab2list(?SERVER).

%%%===================================================================
%%% regine callbacks
%%%===================================================================

init([]) ->
    ets:new(?SERVER, [ordered_set, named_table, public, {keypos, 1}]),
    {ok, #state{}}.

handle_register(Pid, Name, IP, State) ->
    ets:insert_new(?SERVER, {Name, Pid}),
    ets:insert_new(?SERVER, {IP, Pid}),
    {ok, [Name, IP], State}.

handle_unregister(Key, Name, State) ->
    unregister(Key, State),
    unregister(Name, State).

handle_pid_remove(_Pid, Keys, State) ->
    lists:foreach(fun(Key) -> ets:delete(?SERVER, Key) end, Keys),
    State.

handle_death(_Pid, _Reason, State) ->
    State.

terminate(_Reason, _State) ->
	ok.

%%%===================================================================
%%% Internal functions
%%%===================================================================

unregister(Key, State) ->
    Pids = case ets:lookup(?SERVER, Key) of
	       [{Key, Pid}] ->
		   ets:delete(?SERVER, Key),
		   [Pid];
	       _ -> []
	   end,
    {Pids, State}.
