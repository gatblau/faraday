# Agentic search, and where Faraday fits

Agentic search needs the AI to reach the company's real systems as the real user. That
creates a safety problem. This note describes the problem, then describes how Faraday's
design addresses it. Whether Faraday is the right tool for a given deployment is a
separate decision.

---

## The everyday problem

Ask most company search tools a real question — *"When does Project Apollo launch,
and who's the lead engineer?"* — and you get a list of links. Some are current, some
are two years old, some you can't open. It's left to you to read them, decide which to
trust, and put the answer together.

The smarter tools usually work by copying every document in the company into one big
searchable database in advance. That sounds thorough, but it tends to go wrong in
three ways:

- **It mixes old with new.** Several versions of the same plan sit in the database, so
  the answer blends last year's date with this year's.
- **It goes stale.** Documents change daily; the database is only rebuilt on a
  schedule, so it's often hours or days behind.
- **It's hard to keep private.** Once everything is in one place, stopping the intern
  from seeing the salary spreadsheet is difficult and easy to get wrong.

The copy-everything approach isn't all bad. Its one real strength is that, once the
work is done up front, each answer is a fast lookup. Learning as you ask trades some of
that speed away — it can do more work at the moment you ask, so a single answer may be
a little slower or use more computing power — in return for staying current and
private. It's a choice about when you do the work, not a clean win, and many real
systems blend the two. The rest of this note follows the learn-as-you-ask end, because
that's the part that needs Faraday.

---

## The idea: a memory that keeps itself current

Agentic search takes a different approach. Instead of copying everything up front, it
learns as people ask.

The first time someone asks about Project Apollo, the agent reads the relevant
document and writes a short summary: *"Apollo launches 12 October, lead engineer
Sarah, owned by Team Alpha."* It records which document the facts came from. Over
time these summaries become a shared memory — a plain-language record of what the
company knows, built from the questions people actually ask.

The summaries are linked to each other: *Apollo* points to *Team Alpha*, *Team Alpha*
points to *Sarah*. A question that spans several documents is answered by following
those links, not by re-reading ten files.

---

## How it stays current: a four-step loop

Every question runs the same loop:

```
1. ASK     "When does Project Apollo launch?"
2. CHECK   The memory says 12 October, from Document A.
           → Has Document A changed since the note was written?
3. UPDATE  No  → trust the note, answer now.
           Yes → re-read Document A, rewrite the note, then answer.
4. ANSWER  Give the answer and say where it came from.
```

The cheap part is the check. Working out whether a document changed does not mean
re-reading it. Every document carries a last-edited date. The agent compares that date
against the one stored with its note. If they match, the note is still good and the
answer is instant. Only when the date has moved does it re-read and rewrite. You pay
to read a document only when it has actually changed, and the system gets faster the
more it is used.

---

## The hard part: making it safe

The loop is simple. Making it safe is not, and that's where most of these systems stall
after the demo.

To answer one question, the agent has to reach into the company's real systems — the
wiki, the code repository, the ticketing tool — and it has to do so **as the person
asking**. The intern's question must hit a wall the executive's sails through.
Underneath, an AI is writing the steps that make those calls. That AI can be tricked:
a booby-trapped wiki page can carry hidden instructions, and the small programs the AI
writes could walk off with the company's credentials if you're not careful.

So the real requirements are:

- It has to call **many real systems** to answer one question.
- It must do so **with each user's own permissions**, never more.
- The credentials for those systems must **never** reach the AI or the code it wrote.
- Every step must be **logged**, so you can see where an answer came from.

Get any of these wrong and the result is a data leak with a chat box on the front.

---

## How Faraday addresses it

Faraday's design rests on two ideas.

**1. A sealed sandbox.** The small programs the AI writes — short Python scripts — run
inside a sealed environment. Inside, there is no way to open the internet, read the
disk, or start other programs — not blocked, but absent. There is one way out, and
nothing else. Even if someone found a flaw in the sandbox itself, there are no
credentials inside it to steal.

**2. A broker that holds the credentials.** That one exit leads to a trusted broker,
and the broker is the only thing that holds the company's credentials. When a program
needs the wiki, it asks the broker; the broker makes the call **as the person who
asked the original question** and returns only the result. The credential never enters
the sandbox.

Mapped to the requirements above:

| Requirement | How the design meets it |
|---|---|
| Reach many systems to answer one question | The AI writes one small program that makes all the calls in sequence, instead of pausing to think after every step. |
| Act with each user's own permissions | The broker calls every system as that user. The intern's request gets the system's own "access denied"; existing permissions do the policing. |
| Never let credentials reach the AI or its code | The credentials stay with the broker, outside the sandbox. A tricked program can't leak a credential it was never given. |
| Limit booby-trapped documents | What a program reads back is marked untrusted and is not fed straight back to the AI to act on. This contains a hidden instruction in a wiki page; it does not remove the risk, which is why responses are kept at arm's length rather than trusted. |
| Stay inside agreed limits | An administrator sets an approved list of systems and addresses; the program can reach those and nothing else. |
| Show its work | Every call is written to an audit log — the trail of where each fact came from, which is also what lets the answer cite its sources. |

In short, the sandbox keeps the AI's code from reaching anything directly, and the
broker makes the calls on its behalf so no credential ever enters the sandbox.

---

## Where the credential lives: laptop or server?

There is always a broker on the laptop — it is the one door out of the sandbox. The
judgement call is where each system's *credential* lives, and you make it once per
system you connect.

**On the laptop, next to the sandbox.** For some systems, the laptop can get a working
credential by itself, the same way you already sign in to that system through your
company login. The local broker holds it next to the sandbox but outside it, so the
AI's code still never touches it, and makes the call itself. For these systems, that's
the whole solution. No server needed.

**On a separate server you control.** For other systems — usually the sensitive
internal ones — the laptop arrangement either isn't safe or isn't allowed. Then the
local broker doesn't hold a credential at all. It passes the user's sign-in proof to a
separate server, and that server holds the real credential, makes the call, and returns
only the result. The laptop never holds a working credential to that system.

Three questions tell you which is which:

1. **Will your company let a laptop fetch a working credential for this system on its
   own?** Many internal systems are set up so that only a trusted server is allowed to.
2. **Will the system accept a credential that came from a laptop?** Some only trust
   calls from a registered server and turn away a laptop's credential, even with the
   right person's identity on it.
3. **Is it safe for every employee's laptop to hold a working credential to this
   system?** A stolen or infected laptop could reuse it. Fine for a low-stakes wiki;
   not fine for payroll or source control across thousands of laptops.

If all three answers are yes, keep the credential on the laptop. If any answer is no,
it belongs on the server. A public wiki the whole company can already reach is usually
a laptop case; a sensitive internal service is usually a server case. You decide per
system, not once for everything.

**The shortcut to avoid.** It's tempting to set every system up so laptops fetch their
own credentials and skip the server. That isn't a shortcut — it turns every laptop into
a holder of working credentials to the whole company, so one lost laptop reaches
everything. That's the risk most security teams won't take, and it's why the
server-side broker exists.

---

## The boundary: what Faraday covers, what it doesn't

- **Faraday covers** the sandbox, the credential-holding broker, the per-user calls,
  the approved list, and the audit trail — the parts that deal with reaching real
  systems safely.
- **It does not cover** the memory itself — the linked summaries and the service that
  stores them. You build that. To Faraday, that store is just one more system on the
  approved list, reached through the same door as everything else.
- **It does not cover** read-time permission filtering. The memory is shared but
  people's permissions are not, so a fact one person was allowed to learn must not leak
  to someone who wasn't. The per-user check that prevents this — through the broker, as
  that user, before trusting a saved note — uses Faraday's calls, but the logic is
  yours to write.

---

## Summary

Agentic search learns as you ask, remembers in plain language, checks itself before
answering, and cites where it looked. It only works if the AI can act inside real
systems as the real user, with credentials kept out of reach. The sandbox-and-broker
design is one way to meet that constraint; the rest — the memory, the read-time
permission check — sits outside it.
