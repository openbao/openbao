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
 * <Mfa::TotpSelfEnroll @selfEnrollData={{this.model}} @onSuccess={{this.handleSuccess}} />
 * ```
 * @param {object} selfEnrollData - contains all needed information to create the qr code
 * @param {function} onSuccess - called after successful verification
 * @param {function} onError - called when an error happens
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

  @task generateQrCode(totpURL) {
    QRCode.toDataURL(totpURL, {
      errorCorrectionLevel: 'H',
      margin: 2,
      width: 200,
    })
      .then((url) => {
        this.qrCodeDataUrl = url;
      })
      .catch((err) => {
        this.error = 'Failed to generate QR code. Please try again.';
        // eslint-disable-next-line no-console
        console.error(err);
      });
  }

  @task verifyToken() {
    if (!this.totpToken) {
      this.error = 'Please enter a valid totp code code.';
      return;
    }

    this.isVerifying = true;
    this.error = null;
    this.success = false;

    try {
      this.auth.totpVerifySelfEnroll(this.requestID, this.totpToken);

      // if (!response.ok) {
      //   let errorMessage = 'Verification failed. Please check your code and try again.';
      //   try {
      //     const data = response.json();
      //     if (data.errors && data.errors.length) {
      //       errorMessage = data.errors.join(' ');
      //     }
      //   } catch (_) {
      //     // ignore JSON parse errors
      //   }
      //   throw new Error(errorMessage);
      // }

      // Success
      // this.success = true;
      // if (this.args.onSuccess) {
      //   this.args.onSuccess();
      // }
    } catch (err) {
      this.error = err.message || 'An unexpected error occurred.';
    } finally {
      this.isVerifying = false;
    }
  }

  /**
   * Called when the form is submitted.
   */
  @action
  submit(event) {
    event.preventDefault();
    this.verifyToken.perform();
  }
}
