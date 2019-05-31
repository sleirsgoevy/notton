var timer = 0;
var oldText = null;
var fwdMsg = null;

function Message(msgid)
{
    this.msgid = msgid;
    this.text = null;
    this.author = null;
    this.parent = null;
    this.child = null;
    this.receive_time = timer++;
    this.has_contact = false;
    this.chat = null;
    this.delivered = false;
}

Message.prototype.render = function(forwarded)
{
    var div = document.createElement('div');
    div.className = 'message';
    div.setAttribute('id', 'msg_'+this.msgid);
    if(this.chat && !forwarded)
    {
        div.className += (this.chat.key == this.author?' incoming':(this.delivered?' delivered':' outgoing'));
        div.oncontextmenu = showForwardMenu.bind(this);
    }
    var fwdP = document.createElement('p');
    fwdP.style.color = 'blue';
    if(peers[this.author] && peers[this.author].nickname)
    {
        var nickB = document.createElement('b');
        nickB.appendChild(document.createTextNode('@'+peers[this.author].nickname));
        fwdP.appendChild(nickB);
    }
    else
        fwdP.appendChild(document.createTextNode(this.author));
    div.appendChild(fwdP);
    if(this.child)
        div.appendChild(this.child.render(true));
    else
        div.appendChild(this.renderPreview());
    return div;
}

Message.prototype.renderPreview = function()
{
    if(this.text)
        return document.createTextNode(this.text);
    var comment = 'WTF?';
    if(this.child)
        comment = 'Forwarded message';
    else if(this.has_contact)
        comment = 'Contact';
    var font = document.createElement('b');
    font.style.color = 'blue';
    font.appendChild(document.createTextNode(comment));
    return font;
}

Message.prototype.setDelivered = function()
{
    this.delivered = true;
    if(isRendered)
    {
        var div = document.getElementById('msg_'+this.msgid);
        div.className = div.className.replace(' outgoing', ' delivered');
    }
}

function Peer(key)
{
    this.key = key;
    this.messages = [];
    this.nickname = null;
    if(config.nicknames[this.key])
        this.nickname = config.nicknames[this.key];
}

Peer.prototype.getLastMsgTime = function()
{
    if(this.messages.length)
        return this.messages[this.messages.length - 1].receive_time;
    return -1;
}

Peer.prototype.renderSelf = function()
{
    var tr = document.createElement('tr');
    tr.setAttribute('id', 'peer_'+this.key);
    var td = document.createElement('td');
    td.setAttribute('height', '100px');
    td.setAttribute('valign', 'top');
    tr.appendChild(td);
    td.className = 'peer';
    td.onclick = function()
    {
        if(fwdMsg)
        {
            xhr('/', JSON.stringify(['forward', this.key, fwdMsg.msgid]), function(){});
            send_message();
        }
        this.select();
    }.bind(this);
    var nickP = document.createElement('p');
    nickP.setAttribute('align', 'left');
    td.appendChild(nickP);
    var nickB = document.createElement('b');
    nickP.appendChild(nickB);
    nickB.appendChild(document.createTextNode(this.nickname?('@'+this.nickname):this.key));
    var msgP = document.createElement('p');
    msgP.setAttribute('id', 'msgp_'+this.key);
    td.appendChild(msgP);
    document.getElementById('peers').appendChild(tr);
    this.redrawMSGP();
}

Peer.prototype.redrawMSGP = function()
{
    var self = document.getElementById('msgp_'+this.key);
    while(self.firstChild)
        self.removeChild(self.firstChild);
    if(this.messages.length)
        self.appendChild(this.messages[this.messages.length - 1].renderPreview());
}

Peer.prototype.renderMessages = function()
{
    var span = document.createElement('span');
    span.className = 'msgblk';
    span.setAttribute('id', 'msgblk_'+this.key);
    for(var i = 0; i < this.messages.length; i++)
        span.appendChild(this.messages[i].render());
    document.getElementById('messages').appendChild(span);
}

Peer.prototype.render = function()
{
    this.renderSelf();
    this.renderMessages();
}

Peer.prototype.liftUp = function()
{
    var self = document.getElementById('peer_'+this.key);
    var peers = self.parentNode;
    if(peers.childNodes.length > 1)
    {
        peers.removeChild(self);
        peers.insertBefore(self, peers.firstChild);
    }
}

Peer.prototype.select = function()
{
    var selected = document.getElementsByClassName('selected');
    for(var i = selected.length - 1; i >= 0; i--)
        selected[i].className = selected[i].className.replace(' selected', '');
    document.getElementById('peer_'+this.key).className += ' selected';
    document.getElementById('msgblk_'+this.key).className += ' selected';
    scrollDown(0);
}

var messages = {};
var peers = {};
var isRendered = false;

function stripNickname(s)
{
    if(s.indexOf('@') >= 0)
        return s.substr(0, s.indexOf('@'));
    return s;
}

function freeze(msg)
{
    while(msg.parent)
        msg = msg.parent;
    if(!peers[msg.author])
        peers[msg.author] = new Peer();
    pushMessage(msg.author, msg);
}

function pushMessage(author, msg)
{
    msg.chat = peers[author];
    peers[author].messages.push(msg);
    if(isRendered)
    {
        peers[author].redrawMSGP();
        peers[author].liftUp();
        var msgblk = document.getElementById('msgblk_'+peers[author].key);
        msgblk.appendChild(msg.render());
        if(msgblk.className.indexOf(' selected') >= 0)
            scrollDown(100);
    }
}

function handleEvent(e)
{
    if(e[0] == 'msg_pkt_id')
    {
        if(messages[e[2]])
        {
            messages[e[1]] = messages[e[2]].child = new Message(e[1]);
            messages[e[1]].parent = messages[e[2]];
        }
    }
    else if(e[0] == 'incoming_msg')
    {
        if(!messages[e[1]])
            messages[e[1]] = new Message(e[1]);
        messages[e[1]].author = stripNickname(e[2]);
        messages[e[1]].text = decodeURIComponent(escape(e[3]));
        freeze(messages[e[1]]);
    }
    else if(e[0] == 'was_forwarded')
    {
        if(!messages[e[1]])
            messages[e[1]] = new Message(e[1]);
        messages[e[1]].author = stripNickname(e[2]);
    }
    else if(e[0] == 'incoming_contact')
    {
        if(!messages[e[1]])
            messages[e[1]] = new Message(e[1]);
        messages[e[1]].author = stripNickname(e[2]);
        messages[e[1]].has_contact = true;
        freeze(messages[e[1]]);
    }
    else if(e[0] == 'i_am')
        self_key = e[1];
    else if(e[0] == 'sent')
    {
        if(!messages[e[1]])
            messages[e[1]] = new Message(e[1]);
        messages[e[1]].author = self_key;
        messages[e[1]].text = decodeURIComponent(escape(e[3]));
        pushMessage(e[2], messages[e[1]]);
    }
    else if(e[0] == 'forwarded')
    {
        if(!messages[e[1]])
            messages[e[1]] = new Message(e[1]);
        messages[e[1]].author = self_key;
        messages[e[1]].child = messages[e[3]];
        pushMessage(e[2], messages[e[1]]);
    }
    else if(e[0] == 'delivered')
    {
        if(messages[e[1]])
            messages[e[1]].setDelivered();
    }
}

function xhr(url, req, cb)
{
    var the_xhr = new XMLHttpRequest();
    the_xhr.open('POST', url, true);
    the_xhr.send(req);
    the_xhr.onload = function()
    {
        cb(JSON.parse(the_xhr.responseText));
    }
    the_xhr.onerror = function()
    {
        xhr(url, req, cb);
    }
}

function getSelectedPeer()
{
    var selected = document.getElementsByClassName('selected');
    if(selected.length == 0)
        return null;
    return peers[selected[0].id.split('_')[1]];
}

function renderAll()
{
    var sel = getSelectedPeer();
    var peers_div = document.getElementById('peers');
    while(peers_div.firstChild)
        peers_div.removeChild(peers_div.firstChild);
    var peers_arr = [];
    for(var p in peers)
        peers_arr.push(peers[p]);
    peers_arr.sort(function(a, b)
    {
        return b.getLastMsgTime() - a.getLastMsgTime();
    });
    for(var i = 0; i < peers_arr.length; i++)
        peers_arr[i].render();
    if(!peers_arr.length)
        return;
    if(!sel)
        sel = peers_arr[0];
    sel.select();
}

function poll()
{
    xhr('/', '', function(j)
    {
        if(j)
            handleEvent(j);
        poll();
    });
}

xhr('/config', '', function(j)
{
    config = j;
    for(var i in j.nicknames)
        peers[i] = new Peer(i);
    xhr('/loghistory', '', function(j)
    {
        for(var i = 0; i < j.length; i++)
            handleEvent(j[i]);
        renderAll();
        isRendered = true;
        poll();
    });
});

function scrollDown(delay)
{
    var scroll = document.getElementById('msgScroll');
    var msgs = document.getElementById('messages');
    setTimeout(function()
    {
        scroll.scrollTop = msgs.offsetHeight + 90;
    }, delay);
}

function showForwardMenu()
{
    if(fwdMsg)
        return;
    var msg = document.getElementById('message');
    oldText = msg.value;
    fwdMsg = this;
    msg.value = '';
    msg.placeholder = 'Select a peer to forward to...';
    msg.disabled = true;
    document.getElementById('send_btn').childNodes[0].data = 'Cancel';
    return false;
}

function send_message()
{
    var msg = document.getElementById('message');
    if(fwdMsg)
    {
        fwdMsg = null;
        msg.value = oldText;
        msg.placeholder = 'Type your message...';
        msg.disabled = false;
        document.getElementById('send_btn').childNodes[0].data = 'Send!';
        return;
    }
    if(!msg.value)
        return;
    var peer = getSelectedPeer().key;
    xhr('/', JSON.stringify(["sendmsg", peer, unescape(encodeURIComponent(msg.value))]), function(){});
    msg.value = '';
    scrollDown(100);
}
