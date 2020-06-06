# Discord module for PyLink
#
# Copyright (C) 2018-2019 Ian Carpenter <icarpenter@cultnet.net>
# Copyright (C) 2018-2020 James Lu <james@overdrivenetworks.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program. If not, see <http://www.gnu.org/licenses/>.

__version__ = '0.2.0'

import asyncio
import calendar
import time
import collections
import string
import urllib.parse

from discord import Client
from discord.errors import HTTPException
from discord.enums import ChannelType, Status as DiscordStatus
from discord.permissions import Permissions
from discord.message import Message
from discord.abc import GuildChannel

from pylinkirc import structures, utils
from pylinkirc.classes import *
from pylinkirc.log import log
import pylinkirc
try:
    from pylinkirc.protocols.clientbot import ClientbotBaseProtocol
except ImportError as e:
    raise ImportError("Could not load ClientbotBaseProtocol. Make sure you are running "
                      "PyLink 3.0 or higher (current version: %s)" % pylinkirc.__version__) from e

try:
    import libgravatar
except ImportError:
    libgravatar = None
    log.info('discord: libgravatar not installed - avatar support will be disabled.')

BATCH_DELAY = 0.3  # TODO: make this configurable

class DiscordChannelState(structures.CaseInsensitiveDict):
    @staticmethod
    def _keymangle(key):
        try:
            key = int(key)
        except (TypeError, ValueError):
            raise KeyError("Cannot convert channel ID %r to int" % key)
        return key

class DiscordClient(Client):
    me = None
    status_mapping = {
        DiscordStatus.online: 'Online',
        DiscordStatus.idle: 'Idle',
        DiscordStatus.dnd: 'Do Not Disturb',
        DiscordStatus.invisible: 'Offline',  # not a typo :)
        DiscordStatus.offline: 'Offline',
    }
    _dm_channels = {}

    def __init__(self, protocol):
        self.protocol = protocol
        self._event_thread = None
        loop = asyncio.new_event_loop()
        super().__init__(loop=loop)

    async def on_connect(self):
        self.me = self.user
        self.protocol.connected.set()

    def _burst_guild(self, guild):
        log.info('(%s) bursting guild %s/%s', self.protocol.name, guild.id, guild.name)
        try:
            pylink_netobj = self.protocol._create_child(guild.id, guild.name)
        except ValueError:
            log.debug('(%s) not rebursting guild %s/%s as it already exists', self.protocol.name, guild.id, guild.name, exc_info=True)
            return

        pylink_netobj.uplink = None
        pylink_netobj._guild_name = guild.name

        # Create a user for ourselves.
        member = guild.get_member(self.me.id)
        pylink_netobj.pseudoclient = pylink_netobj.users[self.me.id] = \
            User(pylink_netobj, nick=member.name,
                 ts=calendar.timegm(member.joined_at.timetuple()),
                 uid=self.me.id, server=guild.id)

        for member in guild.members:
            self._burst_new_client(guild, member, pylink_netobj)

        pylink_netobj.connected.set()
        pylink_netobj.call_hooks([None, 'ENDBURST', {}])

    def _update_channel_presence(self, guild, channel, member=None, *, relay_modes=False):
        """
        Updates channel presence & IRC modes for the given member, or all guild members if not given.
        """
        if channel.type == ChannelType.category:
            # XXX: there doesn't seem to be an easier way to get this. Fortunately, there usually
            # aren't too many channels in one guild...
            for subchannel in channel.channels:
                log.debug('(%s) _update_channel_presence: checking channel %s/%s in category %s/%s', self.protocol.name, subchannel.id, subchannel, channel.id, channel)
                self._update_channel_presence(guild, subchannel, member=member, relay_modes=relay_modes)
            return
        elif channel.type != ChannelType.text:
            log.debug('(%s) _update_channel_presence: ignoring non-text channel %s/%s', self.protocol.name, channel.id, channel)
            return

        modes = []
        users_joined = []

        try:
            pylink_netobj = self.protocol._children[guild.id]
        except KeyError:
            log.error("(%s) Could not update channel %s(%s)/%s as the parent network object does not exist", self.protocol.name, guild.id, guild.name, str(channel))
            return

        # Create a new channel if not present
        try:
            pylink_channel = pylink_netobj.channels[channel.id]
            pylink_channel.name = str(channel)
            log.debug("(%s) Retrieved channel %s for channel ID %s", self.protocol.name, pylink_channel, channel.id)
        except KeyError:
            pylink_channel = pylink_netobj.channels[channel.id] = Channel(self, name=str(channel))
            log.debug("(%s) Created new channel %s for channel ID %s", self.protocol.name, pylink_channel, channel.id)

        pylink_channel.discord_id = channel.id
        pylink_channel.discord_channel = channel

        if member is None:
            members = guild.members
        else:
            members = [member]

        for member in members:
            uid = member.id
            try:
                pylink_user = pylink_netobj.users[uid]
            except KeyError:
                log.error("(%s) Could not update user %s(%s)/%s as the user object does not exist", self.protocol.name, guild.id, guild.name, uid)
                return

            channel_permissions = channel.permissions_for(member)
            has_perm = channel_permissions.read_messages
            log.debug('discord: checking if member %s/%s has permission read_messages on %s/%s: %s',
                      member.id, member, channel.id, channel, has_perm)
            #log.debug('discord: channel permissions are %s', str(list(channel_permissions)))
            if has_perm:
                if uid not in pylink_channel.users:
                    log.debug('discord: adding member %s to %s/%s', member, channel.id, channel)
                    pylink_user.channels.add(channel.id)
                    pylink_channel.users.add(uid)

                    # Hide offline users if join_offline_users is enabled
                    if pylink_netobj.join_offline_users or (member.status not in
                                (DiscordStatus.offline, DiscordStatus.invisible)):
                        users_joined.append(uid)

                # Map Discord role IDs to IRC modes
                # e.g. 1234567890: 'op'
                #      2345678901: 'voice'
                role_map = pylink_netobj.serverdata.get('role_mode_map') or {}
                # Track all modes the user is allowed to have, since multiple roles may map to one mode.
                entitled_modes = {irc_mode for role_id, irc_mode in role_map.items() if role_id in member.roles}

                # Optionally burst guild owner as IRC owner (+q)
                if uid == guild.owner_id and pylink_netobj.serverdata.get('show_owner_status', True):
                    entitled_modes.add('owner')
                # Grant +qo and +ao instead of only +q and +a
                if 'owner' in entitled_modes or 'admin' in entitled_modes:
                    entitled_modes.add('op')

                for mode, prefixlist in pylink_channel.prefixmodes.items():
                    modechar = pylink_netobj.cmodes.get(mode)
                    if not modechar:
                        continue

                    # New role added
                    if mode in entitled_modes and uid not in prefixlist:
                        modes.append(('+%s' % modechar, uid))
                    # Matching role removed
                    if mode not in entitled_modes and uid in prefixlist:
                        modes.append(('-%s' % modechar, uid))

            elif uid in pylink_channel.users and not has_perm:
                log.debug('discord: parting member %s from %s/%s', member, channel.id, channel)
                pylink_user.channels.discard(channel.id)
                pylink_channel.remove_user(uid)

                # We send KICK from a server to prevent triggering antiflood mechanisms...
                pylink_netobj.call_hooks([
                    guild.id,
                    'KICK',
                    {
                        'channel': channel.id,
                        'target': uid,
                        'text': "User removed from channel"
                    }
                ])

        # Note: once we've gotten here, it is possible that the channel was removed because the bot
        # no longer has access to it
        if channel.id in pylink_netobj.channels:
            if users_joined:
                pylink_netobj.call_hooks([
                    guild.id,
                    'JOIN',
                    {
                        'channel': channel.id,
                        'users': users_joined,
                        'modes': []
                    }
                ])

            if modes:
                pylink_netobj.apply_modes(channel.id, modes)
                log.debug('(%s) Relaying permission changes on %s/%s as modes: %s', self.protocol.name, member.name,
                          channel, pylink_netobj.join_modes(modes))
                if relay_modes:
                    pylink_netobj.call_hooks([guild.id, 'MODE', {'target': channel.id, 'modes': modes}])

    def _burst_new_client(self, guild, member, pylink_netobj):
        """Bursts the given member as a new PyLink client."""
        uid = member.id

        if not member.name:
            log.debug('(%s) Not bursting user %s as their data is not ready yet', self.protocol.name, member)
            return

        if uid in pylink_netobj.users:
            log.debug('(%s) Not reintroducing user %s/%s', self.protocol.name, uid, member.name)
            pylink_user = pylink_netobj.users[uid]
        elif uid != self.me.id:
            tag = str(member)  # get their name#1234 tag
            username = member.name  # this is just the name portion
            realname = '%s @ Discord/%s' % (tag, guild.name)
            # Prefer the person's guild nick (nick=member.name) if defined
            pylink_netobj.users[uid] = pylink_user = User(pylink_netobj, nick=member.name,
                                                          ident=username, realname=realname,
                                                          host='discord/user/%s' % tag, # XXX make this configurable
                                                          ts=calendar.timegm(member.joined_at.timetuple()), uid=uid, server=guild.id)
            pylink_user.modes.add(('i', None))
            pylink_user.services_account = str(uid)  # Expose their UID as a services account
            if member.bot:
                pylink_user.modes.add(('B', None))
            pylink_user.discord_user = member

            pylink_netobj.call_hooks([
                guild.id,
                'UID',
                {
                    'uid': uid,
                    'ts': pylink_user.ts,
                    'nick': pylink_user.nick,
                    'realhost': pylink_user.realhost,
                    'host': pylink_user.host,
                    'ident': pylink_user.ident,
                    'ip': pylink_user.ip
                }
            ])
        else:
            return
        # Update user presence
        self._update_user_status(guild, uid, member.status)

        # Calculate which channels the user belongs to
        for channel in guild.channels:
            if channel.type == ChannelType.text:
                self._update_channel_presence(guild, channel, member)
        return pylink_user

    def _on_guild_create(self, guild):
        log.info('(%s) got GuildCreate event for guild %s/%s', self.protocol.name, guild.id, guild.name)
        self._burst_guild(guild)

    async def on_guild_available(self, guild):
        self._on_guild_create(guild)

    async def on_guild_join(self, guild):
        self._on_guild_create(guild)

    async def on_guild_update(self, old_guild, guild):
        log.info('(%s) got GuildUpdate event for guild %s/%s', self.protocol.name, guild.id, guild.name)
        try:
            pylink_netobj = self.protocol._children[guild.id]
        except KeyError:
            log.error("(%s) Could not update guild %s/%s as the corresponding network object does not exist", self.protocol.name, guild.id, guild.name)
            return
        else:
            pylink_netobj._guild_name = guild.name

    async def on_guild_remove(self, guild):
        log.info('(%s) Got kicked from guild %s, triggering a disconnect', self.protocol.name, guild.id)
        self.protocol._remove_child(guild.id)

    async def on_guild_unavailable(self, guild):
        log.info('(%s) Guild %s was removed, triggering a disconnect', self.protocol.name, guild.id)
        self.protocol._remove_child(guild.id)

    async def on_member_join(self, member):
        guild = membre.guild
        log.info('(%s) got GuildMemberAdd event for guild %s/%s: %s', self.protocol.name, guild.id, guild.name, member)
        try:
            pylink_netobj = self.protocol._children[guild.id]
        except KeyError:
            log.error("(%s) Could not burst user %s as the parent network object does not exist", self.protocol.name, member)
            return
        self._burst_new_client(guild, member, pylink_netobj)

    async def on_member_update(self, old_member, member):
        guild = member.guild
        log.info('(%s) got GuildMemberUpdate event for guild %s/%s: %s', self.protocol.name, guild.id, guild.name, member)
        try:
            pylink_netobj = self.protocol._children[guild.id]
        except KeyError:
            log.error("(%s) Could not update user %s as the parent network object does not exist", self.protocol.name, member)
            return

        uid = member.id
        pylink_user = pylink_netobj.users.get(uid)
        if not pylink_user:
            self._burst_new_client(guild, member, pylink_netobj)
            return

        # Handle NICK changes
        oldnick = pylink_user.nick
        if pylink_user.nick != member.name:
            pylink_user.nick = member.name
            pylink_netobj.call_hooks([uid, 'NICK', {'newnick': member.name, 'oldnick': oldnick}])

        # Relay permission changes as modes
        for channel in guild.channels:
            if channel.type == ChannelType.text:
                self._update_channel_presence(guild, channel, member, relay_modes=True)

    async def on_member_remove(self, member):
        guild = member.guild
        log.info('(%s) got GuildMemberRemove event for guild %s: %s', self.protocol.name, guild.id, member)
        try:
            pylink_netobj = self.protocol._children[guild.id]
        except KeyError:
            log.debug("(%s) Could not remove user %s as the parent network object does not exist", self.protocol.name, member)
            return

        if member.id in pylink_netobj.users:
            pylink_netobj._remove_client(member.id)
            # XXX: make the message configurable
            pylink_netobj.call_hooks([member.id, 'QUIT', {'text': 'User left the guild'}])

    async def on_webhooks_update(self, channel):
        if channel.id in self.protocol.webhooks:
            log.info('(%s) Invalidating webhook %s due to webhook update on guild %s/channel %s',
                      self.protocol.name, self.protocol.webhooks[channel.id], channel.guild.id, channel.id)
            del self.protocol.webhooks[channel.id]

    def _on_channel_create_or_update(self, channel):
        # Update channel presence via permissions for EVERYONE!
        self._update_channel_presence(channel.guild, channel, relay_modes=True)

    async def on_guild_channel_create(self, channel):
        self._on_channel_create_or_update(channel)

    async def on_guild_channel_update(self, old_channel, channel):
        self._on_channel_create_or_update(channel)

    def _on_channel_delete(self, channel):
        try:
            pylink_netobj = self.protocol._children[channel.guild.id]
        except KeyError:
            log.debug("(%s) Could not delete channel %s as the parent network object does not exist", self.protocol.name, channel)
            return

        if channel.id not in pylink_netobj.channels:  # wasn't a type of channel we track
            return

        # Remove the channel from everyone's channel list
        for u in pylink_netobj.channels[channel.id].users:
            pylink_netobj.users[u].channels.discard(channel.id)
        del pylink_netobj.channels[channel.id]

    async def on_guild_channel_delete(self, channel):
        self._on_channel_delete(channel)

    async def on_private_channel_delete(self, channel):
        self._on_channel_delete(channel)

    def _find_common_guilds(self, uid):
        """Returns a list of guilds that the user with UID shares with the bot."""
        common = []
        for guild in self.guilds:  # Check each guild we know about
            if guild.get_member(uid) is not None:
                common.append(guild.id)
        return common

    async def on_message(self, message):
        subserver = None
        target = None

        # If the bot is the one sending the message, don't do anything
        if message.author.id == self.me.id:
            return
        elif message.webhook_id:  # Ignore messages from other webhooks for now...
            return

        text = message.content
        if not isinstance(message.channel, GuildChannel):
            # This is a DM.
            target = self.me.id
            if message.author.id not in self._dm_channels:
                self._dm_channels[message.author.id] = message.channel

            common_guilds = self._find_common_guilds(message.author.id)

            # If we are on multiple guilds, force the sender to choose a server to send from, since
            # every PyLink event needs to be associated with a subserver.
            if len(common_guilds) > 1:
                log.debug('discord: received DM from %s/%s - forcing guild name disambiguation', message.author.id,
                          message.author)
                fail = False
                guild_id = None
                try:
                    netname, text = text.split(' ', 1)
                except ValueError:
                    fail = True
                else:
                    if netname not in world.networkobjects:
                        fail = True
                    else:
                        guild_id = world.networkobjects[netname].sid
                        # Unrecognized guild or not one in common
                        if guild_id not in self.protocol._children or \
                                guild_id not in common_guilds:
                            fail = True

                if fail:
                    # Build a list of common server *names*
                    common_servers = [nwobj.name for gid, nwobj in self.protocol._children.items() if gid in common_guilds]
                    try:
                        await message.channel.send(
                            "To DM me, please prefix your messages with a guild name so I know where to "
                            "process your messages: **<guild name> <command> <args>**\n"
                            "Guilds we have in common: **%s**" % ', '.join(common_servers)
                        )
                    except:
                        log.exception("(%s) Could not send message to user %s", self.name, message.author)
                    return
                else:
                    log.debug('discord: using guild %s/%s for DM from %s/%s', world.networkobjects[netname].sid, netname,
                              message.author.id, message.author)
                    subserver = guild_id
            elif common_guilds:
                # We should be on at least one guild, right?
                subserver = common_guilds[0]
                log.debug('discord: using guild %s for DM from %s', subserver, message.author.id)
            else:
                log.debug('discord: ignoring message from user %s/%s since we are not in any common guilds',
                          message.author.id, message.author)
                return
        else:
            subserver = message.guild.id
            target = message.channel.id

            def format_user_mentions(u):
                # Try to find the user's guild nick, falling back to the user if that fails
                if message.guild and u.id in message.guild.members:
                    return '@' + message.guild.members[u.id].name
                else:
                    return '@' + str(u)

            # Translate mention IDs to their names
            text = message.clean_content

        if not subserver:
            return

        pylink_netobj = self.protocol._children[subserver]
        author = message.author.id

        def _send(text):
            for line in text.split('\n'):  # Relay multiline messages as such
                pylink_netobj.call_hooks([author, 'PRIVMSG', {'target': target, 'text': line}])

        _send(text)
        # For attachments, just send the link
        for attachment in message.attachments:
            _send(attachment.url)

    async def on_raw_message_edit(self, raw):
        data = raw.data
        if 'content' not in data:
            # Message updates do not necessarily contain all fields, per
            # https://discordapp.com/developers/docs/topics/gateway#message-update
            log.debug('discord: Ignoring message update for %s since the content has not been changed', message)
            return

        if raw.cached_message is not None:
            message = raw.cached_message
            message._update(data)
        else:
            # Fill the fields required by the Message class
            data.setdefault('attachments', [])
            data.setdefault('embeds', [])
            data.setdefault('type', 0)
            data.setdefault('pinned', False)
            data.setdefault('mention_everyone', False)
            data.setdefault('tts', False)
            chan = self.get_channel(raw.channel_id)
            message = Message(state=chan._state, channel=chan, data=data)

        if message.guild:
            # Optionally, allow marking edited channel messages as such.
            subserver = message.guild.id
            pylink_netobj = self.protocol._children[subserver]
            editmsg_format = pylink_netobj.serverdata.get('editmsg_format')
            if editmsg_format:
                try:
                    message.content = editmsg_format % message.content
                except TypeError:
                    log.warning('(%s) Invalid editmsg_format format, it should contain a %%s', pylink_netobj.name)

        return await self.on_message(message)

    def _update_user_status(self, guild, uid, status):
        """Handles a Discord presence status update."""
        pylink_netobj = self.protocol._children.get(guild.id)
        if pylink_netobj:
            try:
                u = pylink_netobj.users[uid]
            except KeyError:
                log.exception('(%s) _update_user_status: could not fetch user %s', self.protocol.name, uid)
                return

            if status != DiscordStatus.online:
                awaymsg = self.status_mapping.get(status, 'Unknown Status')
            else:
                awaymsg = ''

            now_invisible = None
            if not pylink_netobj.join_offline_users:
                if status in (DiscordStatus.offline, DiscordStatus.invisible):
                    # If we are hiding offline users, set a special flag for relay to quit the user.
                    log.debug('(%s) Hiding user %s/%s from relay channels as they are offline', pylink_netobj.name,
                              uid, pylink_netobj.get_friendly_name(uid))
                    now_invisible = True
                    u._invisible = True
                elif (u.away in (self.status_mapping[DiscordStatus.invisible], self.status_mapping[DiscordStatus.offline])):
                    # User was previously offline - burst them now.
                    log.debug('(%s) Rejoining user %s/%s from as they are now online', pylink_netobj.name,
                              uid, pylink_netobj.get_friendly_name(uid))
                    now_invisible = False
                    u._invisible = False

            u.away = awaymsg
            pylink_netobj.call_hooks([uid, 'AWAY', {'text': awaymsg, 'now_invisible': now_invisible}])

    async def on_member_update(self, old_member, member):
        self._update_user_status(member.guild, member.id, member.status)

    def _run_coro(self, coro):
        """
        Run a coroutine and return the result.
        /!\ Must not be called from the event loop thread
        """
        fut = asyncio.run_coroutine_threadsafe(coro, loop=self.loop)
        return fut.result()

    def send(self, chan, *args, **kwargs):
        coro = chan.send(*args, **kwargs)
        return self._run_coro(coro)

    def create_dm(self, user):
        coro = user.create_dm()
        return self._run_coro(coro)

    def webhooks(self, channel):
        coro = channel.webhooks()
        return self._run_coro(coro)

    def webhook_execute(self, webhook, *args, **kwargs):
        coro = webhook.execute(*args, **kwargs)
        return self._run_coro(coro)

    def start(self, token):
        name = self.protocol.name
        coro = super().start(token)
        thread = threading.Thread(name="Discord client thread for %s" % name,
                                  target=self.loop.run_until_complete, args=(coro,),
                                  daemon=True)
        thread.start()
        self._event_thread = thread

    def close(self):
        coro = super().close()
        self._run_coro(coro)
        self.loop.stop()
        self._event_thread.join()


class DiscordServer(ClientbotBaseProtocol):
    S2S_BUFSIZE = 0

    def __init__(self, _, parent, server_id, guild_name):
        self.sid = server_id  # Allow serverdata to work first
        self.virtual_parent = parent

        # Convenience variables
        self.client = parent.client
        self.guild = self.client.get_guild(server_id)

        # Try to find a predefined server name; if that fails, use the server id.
        # We don't use the guild name as the PyLink network name because they can be
        # changed at any time, which will break plugins that store data per network.
        fallback_name = 'd%d' % server_id
        name = self.serverdata.get('name', fallback_name)
        if name in world.networkobjects:
            raise ValueError("Attempting to reintroduce network with name %r" % name)

        super().__init__(name)
        self.sidgen = PUIDGenerator('DiscordInternal')
        self.uidgen = PUIDGenerator('PUID')
        self.servers[self.sid] = Server(self, None, str(server_id), internal=False, desc=guild_name)

        self.join_offline_users = self.serverdata.get('join_offline_users', True)
        self.protocol_caps |= {'freeform-nicks', 'virtual-server'}
        self.protocol_caps -= {'can-manage-bot-channels'}

    def _init_vars(self):
        super()._init_vars()
        self.casemapping = 'ascii'  # TODO: investigate utf-8 support
        self.cmodes = {'op': 'o', 'halfop': 'h', 'voice': 'v', 'owner': 'q', 'admin': 'a',
                       '*A': '', '*B': '', '*C': '', '*D': ''}
        self.umodes = {'invisible': 'i', 'bot': 'B'}
        # The actual prefix chars don't matter; we just need to make sure +qaohv are in
        # the prefixmodes list so that the mode internals work properly
        self.prefixmodes = {'q': '~', 'a': '&', 'o': '@', 'h': '%', 'v': '+'}

        # Use an instance of DiscordChannelState, which converts string forms of channels to int
        self._channels = self.channels = DiscordChannelState()

    @property
    def serverdata(self):
        """
        Implements serverdata property for Discord subservers. This merges in the root serverdata config
        block, plus any guild-specific settings for this guild.

        NOTE: serverdata in DiscordServer is not modifiable because it is dynamically generated.
        Changes should instead be made to self.virtual_parent.serverdata
        """
        if getattr(self, 'sid', None):
            data = self.virtual_parent.serverdata.copy()
            guild_data = data.get('guilds', {}).get(self.sid, {})
            log.debug('serverdata: merging data %s with guild_data %s', data, guild_data)
            data.update(guild_data)
            return data
        else:
            log.debug('serverdata: sid not set, using parent data only')
            return self.virtual_parent.serverdata

    @serverdata.setter
    def serverdata(self, value):
        if getattr(self, 'sid', None):
            data = self.virtual_parent.serverdata
            # Create keys if not existing
            if 'guilds' not in data:
                data['guilds'] = {}
            if self.sid not in data['guilds']:
                data['guilds'][self.sid] = {}
            data['guilds'][self.sid].update(value)
        else:
            raise RuntimeError('Cannot set serverdata because self.sid points nowhere')

    def is_nick(self, *args, **kwargs):
        return self.virtual_parent.is_nick(*args, **kwargs)

    def is_channel(self, *args, **kwargs):
        """Returns whether the target is a channel."""
        return self.virtual_parent.is_channel(*args, **kwargs)

    def is_server_name(self, *args, **kwargs):
        """Returns whether the string given is a valid IRC server name."""
        return self.virtual_parent.is_server_name(*args, **kwargs)

    def get_friendly_name(self, *args, **kwargs):
        """
        Returns the friendly name of a SID (the guild name), UID (the nick), or channel (the name).
        """
        return self.virtual_parent.get_friendly_name(*args, caller=self, **kwargs)

    def get_full_network_name(self):
        """
        Returns the guild name.
        """
        return 'Discord/' + self._guild_name

    def is_internal_client(self, uid, **kwargs):
        """Returns whether the given UID is an internal PyLink client."""
        return uid == self.client.me.id or super().is_internal_client(uid, **kwargs)

    def message(self, source, target, text, notice=False):
        """Sends messages to the target."""
        if self.virtual_parent.client.get_user(target) is not None:
            try:
                discord_target = self.client._dm_channels[target]
                log.debug('(%s) Found DM channel for %s: %s', self.name, target, discord_target)
            except KeyError:
                u = self.virtual_parent.client.get_user(target)
                discord_target = self.client._dm_channels[target] = self.client.create_dm(user)
                log.debug('(%s) Creating new DM channel for %s: %s', self.name, target, discord_target)

        elif target in self.channels:
            discord_target = self.channels[target].discord_channel
        else:
            log.error('(%s) Could not find message target for %s', self.name, target)
            return

        if text.startswith('\x01ACTION '):  # Mangle IRC CTCP actions
            # TODO: possibly allow toggling between IRC style actions (* nick abcd) and Discord style (italicize the text)
            text = '\x1d%s' % text[8:-1]
        elif text.startswith('\x01'):
            return  # Drop other CTCPs

        sourceobj = None
        if self.pseudoclient and self.pseudoclient.uid != source:
            sourceobj = self.users.get(source)

        message_data = QueuedMessage(discord_target, target, text, sender=sourceobj, is_notice=notice)
        self.virtual_parent.message_queue.put_nowait(message_data)

    def join(self, client, channel):
        """STUB: Joins a user to a channel."""
        if self.pseudoclient and client == self.pseudoclient.uid:
            log.debug("(%s) discord: ignoring explicit channel join to %s", self.name, channel)
            return
        elif channel not in self.channels:
            log.warning("(%s) Ignoring attempt to join unknown channel ID %s", self.name, channel)
            return
        self.channels[channel].users.add(client)
        self.users[client].channels.add(channel)

        log.debug('(%s) join: faking JOIN of client %s/%s to %s', self.name, client,
                  self.get_friendly_name(client), channel)
        self.call_hooks([client, 'CLIENTBOT_JOIN', {'channel': channel}])

    def nick(self, source, newnick):
        """
        Changes the nick of the main PyLink bot or a virtual client.
        """
        if self.pseudoclient.uid == source:
            my_member = self.guild.get_member(self.client.me)
            my_member.set_nickname(newnick)
        elif self.is_internal_client(source):
            super().nick(source, newnick)
        # Note: Forcing nick changes for others is not yet implemented in the PyLink API.

    def send(self, data, queue=True):
        log.debug('(%s) Ignoring attempt to send raw data via child network object', self.name)
        return

    @staticmethod
    def wrap_message(source, target, text):
        """
        STUB: returns the message text wrapped onto multiple lines.
        """
        return [text]

class QueuedMessage:
    def __init__(self, channel, pylink_target, text, sender=None, is_notice=False):
        """
        Creates a queued message for Discord.

        channel: the target Discord channel (discord.abc.Messageable)
        pylink_target: the original PyLink message target (int, Discord UID or channel ID)
        text: the message text (str)
        sender: optionally, a PyLink User object corresponding to the sender
        is_notice: whether this message corresponds to an IRC notice (bool)
        """
        self.channel = channel
        self.pylink_target = pylink_target
        self.text = text
        self.sender = sender
        self.is_notice = is_notice

class PyLinkDiscordProtocol(PyLinkNetworkCoreWithUtils):
    S2S_BUFSIZE = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if 'token' not in self.serverdata:
            raise ProtocolError("No API token defined under server settings")

        self.client = DiscordClient(self)

        self._children = {}
        self.message_queue = queue.Queue()
        self.webhooks = {}
        self._message_thread = None

    @staticmethod
    def is_nick(s, nicklen=None):
        return True

    def is_channel(self, s):
        """Returns whether the target is a channel."""
        try:
            chan = int(s)
        except (TypeError, ValueError):
            return False
        return self.client.get_channel(chan) is not None

    def is_server_name(self, s):
        """Returns whether the string given is a valid IRC server name."""
        return self.client.get_guild(s) is not None

    def is_internal_client(self, uid):
        """Returns whether the given client is an internal one."""
        if uid == self.client.me.id:
            return True
        return super().is_internal_client(uid)

    def get_friendly_name(self, entityid, caller=None):
        """
        Returns the friendly name of a SID (the guild name), UID (the nick), or channel (the name).
        """
        # internal PUID, handle appropriately
        if isinstance(entityid, str) and '@' in entityid:
            if entityid in self.users:
                return self.users[entityid].nick
            elif caller and entityid in caller.users:
                return caller.users[entityid].nick
            else:
                # Probably a server
                return entityid.split('@', 1)[0]

        if self.is_channel(entityid):
            return str(self.client.get_channel(entityid))
        elif self.client.get_user(entityid) is not None:
            return self.client.get_user(entityid).name
        elif self.is_server_name(entityid):
            return self.client.get_guild(entityid).name
        else:
            raise KeyError("Unknown entity ID %s" % str(entityid))

    @staticmethod
    def wrap_message(source, target, text):
        """
        STUB: returns the message text wrapped onto multiple lines.
        """
        return [text]

    def _get_webhook(self, channel):
        """
        Returns the webhook saved for the given channel, or try to create one if none exists.
        """
        if channel.id in self.webhooks:  # We've already saved this webhook
            wh = self.webhooks[channel.id]
            log.debug('discord: Using saved webhook %s (%s) for channel %s', wh.id, wh.name, channel)
            return wh

        # Generate a webhook name based off a configurable prefix and the channel ID
        webhook_name = '%s-%d' % (self.serverdata.get('webhook_name') or 'PyLinkRelay', channel.id)

        for wh in self.client.webhooks(channel):
            if wh.name == webhook_name:  # This hook matches our name
                self.webhooks[channel.id] = wh
                log.info('discord: Using existing webhook %s (%s) for channel %s', wh.id, webhook_name, channel)
                return wh

        # If we didn't find any webhooks, create a new one
        wh = self.webhooks[channel.id] = channel.create_webhook(name=webhook_name)
        log.info('discord: Created new webhook %s (%s) for channel %s', wh.id, wh.name, channel)
        return wh

    def _get_webhook_fields(self, user):
        """
        Returns a dict of Relay substitution fields for the given User object.
        This attempts to find the original user via Relay if the .remote metadata field is set.

        The output includes all keys provided in User.get_fields(), plus the following:
            netname: The full network name of the network 'user' belongs to
            nettag: The short network tag of the network 'user' belongs to
            avatar: The URL to the user's avatar (str), or None if no avatar is specified
        """
        # Try to lookup the remote user data via relay metadata
        if hasattr(user, 'remote'):
            remotenet, remoteuid = user.remote
            try:
                netobj = world.networkobjects[remotenet]
                user = netobj.users[remoteuid]
            except LookupError:
                netobj = user._irc

        fields = user.get_fields()
        fields['netname'] = netobj.get_full_network_name()
        fields['nettag'] = netobj.name

        default_avatar_url = self.serverdata.get('default_avatar_url')
        avatar = None
        # XXX: we'll have a more rigorous matching system later on
        if user.services_account in self.serverdata.get('avatars', {}):
            avatar_url = self.serverdata['avatars'][user.services_account]
            p = urllib.parse.urlparse(avatar_url)
            log.debug('(%s) Got raw avatar URL %s for user %s', self.name, avatar_url, user)

            if p.scheme == 'gravatar' and libgravatar:  # gravatar:hello@example.com
                try:
                    g = libgravatar.Gravatar(p.path)
                    log.debug('(%s) Using Gravatar email %s for user %s', self.name, p.path, user)
                    avatar = g.get_image(use_ssl=True)
                except:
                    log.exception('Failed to obtain Gravatar image for user %s/%s', user, p.path)

            elif p.scheme in ('http', 'https'):  # a direct image link
                avatar = avatar_url

            else:
                log.warning('(%s) Unknown avatar URI %s for user %s', self.name, avatar_url, user)
        elif default_avatar_url:
            log.debug('(%s) Avatar not defined for user %s; using default avatar %s', self.name, user, default_avatar_url)
            avatar = default_avatar_url
        else:
            log.debug('(%s) Avatar not defined for user %s; using default webhook avatar', self.name, user)
        fields['avatar'] = avatar
        return fields

    MAX_MESSAGE_SIZE = 2000
    def _message_builder(self):
        """
        Discord message queue handler. Also supports virtual users via webhooks.
        """
        def _send(sender, channel, pylink_target, message_parts):
            """
            Wrapper to send a joined message.
            """
            text = '\n'.join(message_parts)

            # Handle the case when the sender is not the PyLink client (sender != None)
            # For channels, use either virtual webhook users or CLIENTBOT_MESSAGE forwarding (relay_clientbot).
            if sender:
                user_fields = self._get_webhook_fields(sender)

                if isinstance(channel, GuildChannel):  # This message belongs to a channel
                    netobj = self._children[channel.guild.id]

                    # Note: skip webhook sending for messages that contain only spaces, as that fails with
                    # 50006 "Cannot send an empty message" errors
                    if netobj.serverdata.get('use_webhooks') and text.strip():
                        user_format = netobj.serverdata.get('webhook_user_format', "$nick @ $netname")
                        tmpl = string.Template(user_format)
                        webhook_fake_username = tmpl.safe_substitute(self._get_webhook_fields(sender))

                        try:
                            webhook = self._get_webhook(channel)
                            self.client.webhook_execute(webhook, content=text[:self.MAX_MESSAGE_SIZE], username=webhook_fake_username, avatar_url=user_fields['avatar'])
                        except HTTPException as e:
                            if e.code == 10015 and channel.id in self.webhooks:
                                log.info("(%s) Invalidating webhook %s for channel %s due to Unknown Webhook error (10015)",
                                         self.name, self.webhooks[channel.id], channel)
                                del self.webhooks[channel.id]
                            elif e.code == 50013:
                                # Prevent spamming errors: disable webhooks we don't have the right permissions
                                log.warning("(%s) Disabling webhooks on guild %s/%s due to insufficient permissions (50013). Rehash to re-enable.",
                                            self.name, channel.guild.id, channel.guild.name)
                                self.serverdata.update(
                                    {'guilds':
                                        {channel.guild.id:
                                            {'use_webhooks': False}
                                        }
                                    })
                            else:
                                log.error("(%s) Caught API exception when sending webhook message to channel %s: %s/%s", self.name, channel, e.response.status_code, e.code)
                            log.debug("(%s) HTTPException full traceback:", self.name, exc_info=True)

                        except:
                            log.exception("(%s) Failed to send webhook message to channel %s", self.name, channel)
                        else:
                            return

                    for line in message_parts:
                        netobj.call_hooks([sender.uid, 'CLIENTBOT_MESSAGE', {'target': pylink_target, 'text': line}])
                    return
                else:
                    # This is a forwarded PM - prefix the message with its sender info.
                    pm_format = self.serverdata.get('pm_format', "Message from $nick @ $netname: $text")
                    user_fields['text'] = text
                    text = string.Template(pm_format).safe_substitute(user_fields)

            try:
                self.client.send(channel, text[:self.MAX_MESSAGE_SIZE])
            except Exception as e:
                log.exception("(%s) Could not send message to channel %s (pylink_target=%s)", self.name, channel, pylink_target)

        joined_messages = collections.defaultdict(collections.deque)
        while not self._aborted.is_set():
            try:
                # message is an instance of QueuedMessage (defined in this file)
                message = self.message_queue.get(timeout=BATCH_DELAY)
                message.text = utils.strip_irc_formatting(message.text)

                if not self.serverdata.get('allow_mention_everyone', False):
                    message.text = message.text.replace('@here', '@ here')
                    message.text = message.text.replace('@everyone', '@ everyone')

                # First, buffer messages by channel
                joined_messages[message.channel].append(message)

            except queue.Empty:  # Then process them together when we run out of things in the queue
                for channel, messages in joined_messages.items():
                    next_message = []
                    length = 0
                    current_sender = None
                    # We group messages here to avoid being throttled as often. In short, we want to send a message when:
                    # 1) The virtual sender (for webhook purposes) changes
                    # 2) We reach the message limit for one batch (2000 chars)
                    # 3) We run out of messages at the end
                    while messages:
                        message = messages.popleft()
                        next_message.append(message.text)
                        length += len(message.text)

                        if message.sender != current_sender or length >= self.MAX_MESSAGE_SIZE:
                            current_sender = message.sender
                            _send(current_sender, channel, message.pylink_target, next_message)
                            next_message.clear()
                            length = 0

                    # The last batch
                    if next_message:
                        _send(current_sender, channel, message.pylink_target, next_message)

                joined_messages.clear()
            except Exception:
                log.exception("Exception in message queueing thread:")

    def _create_child(self, server_id, guild_name):
        """
        Creates a virtual network object for a server with the given name.
        """
        # This is a bit different because we let the child server find its own name
        # and report back to us.
        child = DiscordServer(None, self, server_id, guild_name)
        world.networkobjects[child.name] = self._children[server_id] = child
        return child

    def _remove_child(self, server_id):
        """
        Removes a virtual network object with the given name.
        """
        pylink_netobj = self._children[server_id]
        pylink_netobj.call_hooks([None, 'PYLINK_DISCONNECT', {}])
        del self._children[server_id]
        del world.networkobjects[pylink_netobj.name]

    def connect(self):
        self._aborted.clear()
        self._message_thread = threading.Thread(name="Messaging thread for %s" % self.name,
                                                target=self._message_builder, daemon=True)
        self._message_thread.start()
        self.client.start(self.serverdata['token'])

    def disconnect(self):
        """Disconnects from Discord and shuts down this network object."""
        self._aborted.set()

        self._pre_disconnect()

        children = self._children.copy()
        for child in children:
            self._remove_child(child)

        self.client.close()

        self._post_disconnect()

Class = PyLinkDiscordProtocol
