%% Copyright 2016, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(gtp_u_proxy).

%% A GTP-U proxy instance is described by
%%  * GRX IP and sending port
%%  * Proxy IP and sending port
%%
%% It will open the GTPv1-U port (2152) for recieving
%% and open the specified sending ports on the GRP and
%% Proxy IP's

-behaviour(gen_server).

%% API
-export([start_link/4]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(GTP_U_PORT, 2152).

-record(state, {name, recv, send}).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link(Name, Port, IP, Opts) ->
    gen_server:start_link(?MODULE, [Name, Port, IP, Opts], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init([Name, Port, IP, Opts]) ->
    {ok, Recv} = gtp_open_port(?GTP_U_PORT, IP, Opts),
    {ok, Send} = gtp_open_port(Port, IP, Opts),

    gtp_u_proxy_reg:register(Name, IP),
    State = #state{name = Name,
		   recv = Recv,
		   send = Send},
    {ok, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
ipv6opts(IP, Opts) when is_list(IP) ->
    {ok, Addr} = inet:parse_address(IP),
    ipv6opts(Addr, Opts);
ipv6opts(IP = {_,_,_,_,_,_,_,_}, Opts) ->
    [inet6, {ipv6_v6only, true}, {ip, IP} | Opts];
ipv6opts(IP = {_,_,_,_}, Opts) ->
    [{ip, IP} | Opts];
ipv6opts(_, Opts) ->
    Opts.

gtp_open_port(Port, IP, Opts0) ->
    Opts = ipv6opts(IP, Opts0),
    gen_udp:open(Port, [binary, {active, once}, {reuseaddr, true} | Opts]).
