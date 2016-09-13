%% Copyright 2016, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(gtp_u_edp).

-compile({parse_transform, cut}).

-behaviour(gen_server).

%% API
-export([start_link/0]).
-export([register/2, lookup/1, port_foreach/2]).
-export([all/0]).

%% regine_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 code_change/3, terminate/2]).

%% --------------------------------------------------------------------
%% Include files
%% --------------------------------------------------------------------
-include_lib("stdlib/include/ms_transform.hrl").

-define(SERVER, 'gtp-u').

-record(state, {}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

register(Port, TEI) ->
    gen_server:call(?SERVER, {register, self(), {Port, TEI}}).

lookup(Key) ->
    case ets:lookup(?SERVER, Key) of
	[{Key, Pid, _}] ->
	    Pid;
	_ ->
	    undefined
    end.

port_foreach(Fun, Name) ->
    Ms = ets:fun2ms(fun({{Port, _TEI}, Pid, _MRef}) when Port =:= Name -> Pid end),
    ets:safe_fixtable(?SERVER, true),
    port_foreach_do(Fun, ets:select(?SERVER, Ms, 1)),
    ets:safe_fixtable(?SERVER, false),
    ok.

all() ->
    ets:tab2list(?SERVER).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    ets:new(?SERVER, [ordered_set, named_table, public, {keypos, 1}]),
    {ok, #state{}}.

handle_call({register, Pid, Key}, _From, State) ->
    MRef = erlang:monitor(process, Pid),
    ets:insert_new(?SERVER, {Key, Pid, MRef}),
    {reply, ok, State};

handle_call({bind, Port}, _From, State) ->
    Reply = gtp_u_edp_port:bind(Port),
    {reply, Reply, State};

handle_call(_Request, _From, State) ->
    lager:warning("EDP: unhandled call ~p, from ~p", [_Request, _From]),
    {reply, ok, State}.

handle_cast(_Cast, State) ->
    {noreply, State}.

handle_info({'DOWN', MonitorRef, process, _Pid, _Info}, State) ->
    MS = ets:fun2ms(fun(Obj = {_Key,_P, MRef}) when MRef == MonitorRef -> Obj end),
    lists:foreach(ets:delete_object(?SERVER, _), ets:select(?SERVER, MS)),
    {noreply, State}.

terminate(_Reason, _State) ->
	ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

port_foreach_do(_Fun, '$end_of_table') ->
    ok;
port_foreach_do(Fun, {[Pid], Continuation}) ->
    Fun(Pid),
    port_foreach_do(Fun, ets:select(Continuation)).
