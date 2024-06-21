/**
 * Created by pliuzzi on 21/06/24.
 */

import {api, LightningElement} from 'lwc';
import {sign} from "./sign";
import {NavigationMixin} from "lightning/navigation";

const generateRandomString = (length = 15) => Math.random().toString(20).substring(2, length)

export default class TestSignature extends NavigationMixin(LightningElement) {

  @api recordId;

  retUrlSigned;

  async onCalculateSignatureClick(event) {
    const retUrl = 'com.salesforce.fieldservice://v1/sObject/' + generateRandomString();
    let datiGeneraliUrl = 'https://youreka.io/yourekamobile'
    datiGeneraliUrl += '?formID=' + generateRandomString();
    const retUrlDecoded = decodeURIComponent(retUrl)
    const retUrlSignature = await sign(retUrlDecoded);
    this.retUrlSigned = encodeURIComponent(retUrlDecoded + '?__signature=') + retUrlSignature;
    datiGeneraliUrl += '&promptReturn=false&retURL=' + this.retUrlSigned + '';
    console.log('retUrlSigned', this.retUrlSigned);
    this[NavigationMixin.Navigate]({
      type: 'standard__webPage',
      attributes: {
        url: datiGeneraliUrl
      }
    });
  }

}