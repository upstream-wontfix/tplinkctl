# Disclaimer

**Read this before installing or running tplinkctl. By using, copying,
modifying or distributing this software you acknowledge and accept everything
below.**

## AI-generated code

Most of this project's code, tests and documentation were written with the help
of an AI coding assistant (Anthropic's Claude). AI-generated code can contain
mistakes, security weaknesses or behaviour that doesn't match its documentation,
even when it appears to work. **Inspect, review and test the code yourself
before running it**, especially before using any feature that sends data to a
router or changes its settings.

## No warranty

This software is provided **"AS IS"**, without warranty of any kind, express or
implied. That includes, but is not limited to, the implied warranties of
merchantability, fitness for a particular purpose, accuracy, and
non-infringement. The entire risk as to the quality, performance and results of
using it is with you. Should it prove defective, you assume the cost of all
necessary servicing, repair or correction.

## Limitation of liability

To the maximum extent permitted by applicable law, in no event will the author(s)
or contributors be liable to you or anyone else for any damages of any kind. That
includes direct, indirect, incidental, special, exemplary or consequential damages,
loss of data, loss of connectivity, loss of service, misconfigured or unusable
devices, security incidents, or costs of substitute goods or services. This
applies however the damage was caused and under any theory of liability (contract,
strict liability, tort including negligence, or otherwise), even if advised of the
possibility of such damage.

Sections 15 and 16 of the GNU General Public License v3 (see [LICENSE](LICENSE))
also apply and take precedence where they offer broader protection.

## Your responsibilities

- **Authorisation.** Only use this tool on routers you own or are explicitly
  authorised to administer. Accessing network equipment without permission may
  be illegal where you live.
- **Credentials.** You are responsible for storing your router password securely.
  The tool reads it from a local file or environment variable and sends it only
  to the router you configure. Verify this in the code yourself.
- **Side effects of normal use.** Even read-only commands log in to the router.
  That logs out anyone using the router's web interface, and each failed login
  counts toward the router's login lockout.
- **Changes.** The `write` command and `Router.request(..., allow_write=True)`
  send arbitrary operations to the router. They can change settings, disconnect
  devices, cut off your own access, or leave the router in a state that needs a
  factory reset. Back up your router configuration first, and use them only if
  you understand the exact request being sent.
- **Diagnostics are heuristics.** `tplink diagnose` reports patterns that often
  indicate problems. It can miss real problems and flag harmless ones. It is not
  professional network, security or legal advice.
- **Compatibility.** It has only been tested on a small number of router models
  and firmware versions. Behaviour on other models is unknown.

## Not affiliated with TP-Link

This is an independent, unofficial project. It is not affiliated with, endorsed
by, or supported by TP-Link Systems Inc. or its affiliates. "TP-Link", "Archer",
"Deco" and related names are trademarks of their respective owners and are used
here only to describe compatibility.

## Third-party software

tplinkctl depends on [tplinkrouterc6u](https://github.com/AlexandrErohin/TP-Link-Archer-C6U)
(GPL-3.0-or-later) and its dependencies, which are separate projects under their
own licenses and maintained by their own authors. Their disclaimers apply to
their code.
