package ngap

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	gmm_common "github.com/free5gc/amf/internal/gmm/common"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/nas/ie"
	nas_message "github.com/free5gc/nas/message"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

// Issue #1084: a second device presents an unknown GUTI, then returns the same
// SUCI as a connected subscriber. Exercise real NAS authentication/security mode
// control and NGAP release with HTTP peers, including an existing SMF session
// and PCF association. The Identity Response is only a candidate, never proof.
func TestIdentityResponseCollision(t *testing.T) {
	previousConfig := factory.AmfConfig
	factory.AmfConfig = &factory.Config{Configuration: &factory.Configuration{}}
	t.Cleanup(func() { factory.AmfConfig = previousConfig })
	_, consumerErr := consumer.NewConsumer(nil)
	require.NoError(t, consumerErr)
	const access = models.AccessType_3_GPP_ACCESS

	for _, scenario := range []string{
		"release complete", "local reset", "authentication failure", "invalid security mode MAC", "different SUPI",
	} {
		t.Run(scenario, func(t *testing.T) {
			supi := victimSupi
			if scenario == "different SUPI" {
				supi = otherSupi
			}
			peers := newCorePeers(t, supi)
			self := amf_context.GetSelf()
			NewAmfContext(self)
			self.NrfUri = peers.URL
			victim := registeredVictim(t, peers)
			policy := &models.Pcf_AMPolCtrl_PolicyAssociation{}
			victim.AmPolicyAssociation = policy
			victim.PolicyAssociationId = "existing-policy"
			victim.PcfUri = peers.URL
			old := newAir(t, access)
			oldRanUe, err := old.ran.NewRanUe(7)
			require.NoError(t, err)
			gmm_common.AttachRanUeToAmfUeAndReleaseOldIfAny(victim, oldRanUe)
			// The other access and its session must survive an initial registration.
			other := newAir(t, models.AccessType_NON_3_GPP_ACCESS)
			otherRanUe, err := other.ran.NewRanUe(8)
			require.NoError(t, err)
			victim.AttachRanUe(otherRanUe)
			otherSession := amf_context.NewSmContext(6)
			otherSession.SetAccessType(models.AccessType_NON_3_GPP_ACCESS)
			victim.StoreSmContext(6, otherSession)
			originalGuti := victim.GetGuti()
			a := newAir(t, access)
			unknownGuti := mobileIdentity5GSFromBytes([]uint8{
				0xf2, 0x02, 0xf8, 0x39, 0xca, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x42,
			})
			request := unverifiedRegistrationRequest(ie.RegType_InitialReg, unknownGuti)
			request.Ngksi = &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: ie.NASKeyNA}
			request.PDUSessStatus = nil
			a.initialUEMessage(plainNas(t, request), "", false)
			provisional := a.ranUe.GetAmfUe()
			require.NotSame(t, victim, provisional)
			require.Nil(t, provisional.AuthenticatingFor, "unknown GUTI must not resolve yet")
			t.Cleanup(provisional.Remove)

			unchanged := func() {
				t.Helper()
				require.Same(t, oldRanUe, victim.GetRanUe(access))
				require.Same(t, victim, oldRanUe.GetAmfUe())
				require.Empty(t, old.conn.MsgList, "old gNB released before proof of ownership")
				require.Equal(t, bindingKnasInt, victim.KnasInt)
				require.Equal(t, originalGuti, victim.GetGuti())
				require.Same(t, policy, victim.AmPolicyAssociation)
				_, ok := victim.SmContextFindByPDUSessionID(5)
				require.True(t, ok)
				require.Empty(t, peers.beyondAuthentication())
				stored, ok := self.AmfUeFindBySupi(victimSupi)
				require.True(t, ok)
				require.Same(t, victim, stored)
			}
			unchanged()
			res := akaResStar
			if scenario == "authentication failure" {
				res = bytes.Repeat([]byte{0xff}, 16)
			}
			a.authenticate(res) // includes Identity Response on the unknown-GUTI path
			require.Same(t, victim, provisional.AuthenticatingFor)
			unchanged()
			if scenario == "authentication failure" {
				return
			}
			a.ueSec.UplinkCount.Set(0, 0)
			complete := a.protected(&nas_message.SecModeComplete{
				NASMsgCntr: &ie.NASMsgCntr{Contents: plainNas(t, request)},
			}, nas_message.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx)
			if scenario == "invalid security mode MAC" {
				complete[2] ^= 0xff
			}
			a.uplink(complete)
			if scenario == "invalid security mode MAC" || scenario == "different SUPI" {
				// The different subscriber may register independently; it must never
				// acquire or release this subscriber's resources.
				require.Same(t, oldRanUe, victim.GetRanUe(access))
				require.Empty(t, old.conn.MsgList)
				require.Same(t, policy, victim.AmPolicyAssociation)
				require.Equal(t, originalGuti, victim.GetGuti())
				_, ok := victim.SmContextFindByPDUSessionID(5)
				require.True(t, ok)
				return
			}

			require.Same(t, victim, a.ranUe.GetAmfUe())
			require.Same(t, a.ranUe, victim.GetRanUe(access))
			require.Same(t, otherRanUe, victim.GetRanUe(models.AccessType_NON_3_GPP_ACCESS))
			require.Nil(t, oldRanUe.GetAmfUe(), "old release must not retain ownership of reused context")
			require.Same(t, oldRanUe, self.RanUeFindByAmfUeNgapID(oldRanUe.AmfUeNgapId))
			require.Len(t, old.conn.MsgList, 1)
			released, err := ngapMessage.Parse(old.conn.MsgList[0])
			require.NoError(t, err)
			require.IsType(t, &ngapMessage.UEContextReleaseCommand{}, released)
			require.Same(t, policy, victim.AmPolicyAssociation, "existing policy must remain reachable")
			require.Empty(t, peers.beyondAuthentication(), "no new policy or session release before Registration Complete")
			_, messages := a.sent()
			require.Len(t, messages, 1)
			require.IsType(t, &nas_message.RegAccept{}, messages[0])
			a.uplink(a.protected(&nas_message.RegComplete{}, nas_message.SecHdrTypeIntegrityProtectedAndCiphered))
			require.Contains(t, peers.beyondAuthentication(), "POST /nsmf-pdusession/v1/sm-contexts/smctx-5/release")
			_, exists := victim.SmContextFindByPDUSessionID(5)
			require.False(t, exists)
			retained, exists := victim.SmContextFindByPDUSessionID(6)
			require.True(t, exists)
			require.Same(t, otherSession, retained)

			if scenario == "local reset" {
				removeRan(old.ran)
			} else {
				dispatchMain(old.ran, &ngapMessage.UEContextReleaseComplete{
					AMFUENGAPID: &ngapType.AMFUENGAPID{Value: oldRanUe.AmfUeNgapId},
					RANUENGAPID: &ngapType.RANUENGAPID{Value: oldRanUe.RanUeNgapId},
				}, nil)
			}
			require.Nil(t, self.RanUeFindByAmfUeNgapID(oldRanUe.AmfUeNgapId))
			stored, ok := self.AmfUeFindBySupi(victimSupi)
			require.True(t, ok)
			require.Same(t, victim, stored, "delayed old release removed the reused context")
			require.Same(t, a.ranUe, victim.GetRanUe(access))
			require.Same(t, policy, victim.AmPolicyAssociation)
		})
	}
}
