# Phase 0 evidence

Do not treat this implementation as production-ready until all three spikes pass on the target Linux container host. Unraid is one supported deployment option, not a runtime requirement.

Store dated evidence under an ignored `docs/spikes/evidence/` directory. Include command output, `nft list ruleset`, `ip rule`, all route tables, redacted WireGuard status, packet captures, public-IP results, DNS leak results, host OS and kernel versions, container-engine version, and the exact Tailscale image version.

## Source identity

1. Enroll and approve the container as an exit node.
2. Select it from two Tailscale clients with no assignments configured.
3. Capture `tailscale0` traffic with a temporary diagnostic sidecar. The production agent intentionally lacks `NET_RAW`:

   ```sh
   mkdir -p docs/spikes/evidence
   docker run --rm \
     --network container:tailway-agent \
     --cap-drop ALL \
     --cap-add NET_RAW \
     --cap-add SETUID \
     --cap-add SETGID \
     -v "$PWD/docs/spikes/evidence:/evidence" \
     --entrypoint timeout \
     "local/tailway-agent:${IMAGE_TAG:-dev}" \
     60 tcpdump -nn -i tailscale0 -w /evidence/source-identity.pcap
   ```

4. Confirm both clients' distinct `100.x` source addresses appear before custom NAT and record the conclusion.

Tailscale node authorization and exit-route approval are separate operations. After enrollment, open the machine's route settings in the Tailscale admin console, enable **Use as exit node**, save, and verify that `tailscale exit-node list` on a client includes the gateway.

Failure means this one-identity design must not proceed.

## Proton headless boundary

The shipped adapter is intentionally static. Export WireGuard configurations through Proton's supported account interface and import only those files. Do not add scraping or undocumented Proton APIs to this project.

Record whether the account permits two simultaneous imported configurations and whether the selected servers return the expected countries.

## Concurrent isolation

1. Import two Proton WireGuard configurations.
2. Create both exits in the console.
3. Assign one client to each exit.
4. Verify simultaneous public-IP and DNS results from both clients.
5. Stop one interface with `ip link set proton0 down` inside the agent.
6. Verify only its assigned client fails and neither the home WAN nor the other exit carries its traffic.

If overlapping tunnel addresses cannot coexist, the fixed network-namespace sidecar fallback still needs implementation before release.