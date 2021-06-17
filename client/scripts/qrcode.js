import { BrowserQRCodeReader } from "@zxing/library";

const codeReader = new BrowserQRCodeReader();

export function enableQrScanner(videoEl) {
  return codeReader.decodeOnceFromVideoDevice(undefined, videoEl);
}
