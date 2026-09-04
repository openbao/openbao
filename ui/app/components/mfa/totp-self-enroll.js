import Component from '@glimmer/component';
import { inject as service } from '@ember/service';
import { tracked } from '@glimmer/tracking';
import { action } from '@ember/object';
import { task } from 'ember-concurrency';
import QRCode from 'qrcode';

/**
 * @module TotpSelfEnroll
 * Component to allow for self enrollment
 *
 * @example
 * ```js
 * <Mfa::TotpSelfEnroll @selfEnrollData={{this.model}} @onSuccess={{this.handleSuccess}} @onCancel={{transition-to "vault.cluster.auth"}} />
 * ```
 * @param {object} selfEnrollData - contains all needed information to create the qr code
 * @param {function} onSuccess - called after successful verification
 * @param {function} onCancel - called when the self enrollment was canceled
 */

export default class TotpSelfEnroll extends Component {
  @service auth;

  @tracked totpToken = '';
  @tracked error = null;
  @tracked success = false;
  @tracked qrCodeDataUrl = null;

  @tracked isVerifying = false;

  constructor() {
    super(...arguments);
    if (this.totpSecret && this.totpURL) {
      this.generateQrCode.perform(this.totpURL);
    }
  }

  get totpSecret() {
    return this.args.selfEnrollData.totp_self_enroll.totp_secret;
  }
  get totpURL() {
    return this.args.selfEnrollData.totp_self_enroll.totp_url;
  }
  get requestID() {
    return this.args.selfEnrollData.totp_self_enroll.mfa_request_id;
  }
  get clientToken() {
    return this.args.selfEnrollData.client_token;
  }

  @task *generateQrCode(totpURL) {
    try {
      this.qrCodeDataUrl = yield QRCode.toDataURL(totpURL, {
        errorCorrectionLevel: 'H',
        margin: 2,
        width: 200,
      });
    } catch (err) {
      this.error = ['Failed to generate QR code. Please try again.'];
      // eslint-disable-next-line no-console
      console.error(err);
    }
  }

  @task *confirmSelfEnroll() {
    if (!this.totpToken) {
      this.error = ['Please enter a valid TOTP code.'];
      return;
    }

    this.isVerifying = true;
    this.error = null;
    this.success = false;

    try {
      yield this.auth.totpVerifySelfEnroll(this.requestID, this.totpToken, this.clientToken);

      this.success = true;
      if (this.args.onSuccess) {
        this.args.onSuccess();
      }
    } catch (err) {
      this.error = err ? this.auth.handleError(err) : ['An unexpected error occurred.'];
    } finally {
      this.isVerifying = false;
    }
  }

  @task *revokeSelfEnroll() {
    try {
      yield this.auth.totpRevokeSelfEnroll(this.requestID, this.clientToken);

      if (this.args.onCancel) {
        this.args.onCancel();
      }
    } catch (err) {
      this.error = err ? this.auth.handleError(err) : 'An unexpected error occurred.';
    }
  }

  @action
  submit(event) {
    event.preventDefault();
    this.confirmSelfEnroll.perform();
  }

  @action
  cancel() {
    this.revokeSelfEnroll.perform();
  }
}
