;; Copyright © 2014 Grim Schjetne <grim@schjetne.se>

;; This file is part of CLJWT.

;; CLJWT is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as
;; published by the Free Software Foundation, either version 3 of the
;; License, or (at your option) any later version.

;; CLJWT is distributed in the hope that it will be useful, but
;; WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
;; Lesser General Public License for more details.

;; You should have received a copy of the GNU Lesser General Public
;; License along with CLJWT.  If not, see
;; <http://www.gnu.org/licenses/>.

(in-package #:cl-user)
(defpackage #:cljwt
  (:use #:cl
        #:cl-base64)
  (:import-from #:alexandria
                #:plist-hash-table)
  (:import-from #:flexi-streams
                #:string-to-octets
                #:octets-to-string)
  (:import-from #:ironclad
                #:make-hmac
                #:update-hmac
                #:hmac-digest)
  (:export #:issue
           #:decode
           #:to-unix-time))

(in-package #:cljwt)

(defmacro bind-hash-tables (bindings &body body)
  `(let ,(loop for binding in bindings collect
              (list (car binding)
                    `(etypecase ,(cadr binding)
                       (hash-table ,(cadr binding))
                       (list (plist-hash-table ,(cadr binding)
                                               :test #'equal)))))
     ,@body))

(defmacro add-claims (hash &rest claims)
  `(progn ,@(loop for (key value) on claims by #'cddr collect
                 `(when ,value
                    (setf (gethash ,key ,hash) ,value)))))

(defun to-unix-time (time)
  "Convert universal time to New Jersey time"
  (when time (- time (encode-universal-time 0 0 0 1 1 1970 0))))

(defun from-unix-time (time)
  "Convert New Jersey time to universal time"
  (when time (+ time (encode-universal-time 0 0 0 1 1 1970 0))))


(defun base64-encode (input)
  "Takes a string, returns an unpadded URI-encoded Base64 string.
Necessary because CL-BASE64 has no option to omit padding."
  (with-output-to-string (out)
    (with-input-from-string
        (in
         (etypecase input
           (string (string-to-base64-string input :uri t))
           ((simple-array (unsigned-byte 8))
            (usb8-array-to-base64-string input :uri t))))
      (loop for character = (read-char in nil)
         while character do
           (unless (eq character #\.)
             (write-char character out))))))

(defun base64-decode (base-64-string)
  "Strings must be re-padded or CL-BASE64 gets confused."
  (base64-string-to-usb8-array
   (with-output-to-string (s)
     (write-string base-64-string s)
     (loop repeat (rem (length base-64-string) 4) do
          (write-char #\. s)))
   :uri t))

(defun issue (claims &key algorithm secret issuer subject audience
                       expiration not-before issued-at id more-header)
  "Encodes and returns a JSON Web Token. Times are in universal-time,
number of seconds from 1900-01-01 00:00:00"
  (bind-hash-tables ((claimset claims)
                     (header more-header))
    ;; Add registered claims to the claims hash table
    (add-claims claimset
                "iss" issuer
                "sub" subject
                "aud" audience
                "exp" (to-unix-time expiration)
                "nbf" (to-unix-time not-before)
                "iat" (to-unix-time issued-at)
                "jti" id)
    ;; Add type and algorithm to the header hash table
    (add-claims header
                "typ" "JWT"
                "alg" (ecase algorithm
                        (:none "none")
                        (:hs256 "HS256")))
    ;; Prepare JSON
    (let ((header-string (base64-encode
                          (with-output-to-string (s)
                            (yason:encode header s))))
          (claims-string (base64-encode
                          (with-output-to-string (s)
                            (yason:encode claimset s)))))
      ;; Assemble and, if applicable, sign the JWT
      (format nil "~A.~A.~@[~A~]"
              header-string
              claims-string
              (when (eq algorithm :hs256)
                (HS256-digest header-string
                              claims-string
                              secret))))))

(defun HS256-digest (header-string claims-string secret)
  "Takes header and claims in Base64, secret as a string or octets,
returns the digest, in Base64"
  (base64-encode
   (hmac-digest
    (update-hmac
     (make-hmac (etypecase secret
                  ((simple-array (unsigned-byte 8))
                   secret)
                  (string
                   (string-to-octets secret
                                     :external-format :utf-8)))
                'ironclad:SHA256)
     (concatenate '(vector (unsigned-byte 8))
                  (string-to-octets
                   header-string)
                  #(46) ; ASCII period (.)
                  (string-to-octets
                   claims-string))))))

(defun compare-HS256-digest (header-string claims-string
                             secret reported-digest)
  "Takes header and claims in Base64, secret as a string or octets, and a digest in Base64 to compare with. Signals an error if there is a mismatch."
  (let ((computed-digest
         (HS256-digest header-string
                       claims-string
                       secret)))
    (unless (equalp computed-digest
                   reported-digest)
      (error 'invalid-hmac
             :reported-digest reported-digest
             :computed-digest computed-digest))))

(defun read-until-period (stream)
  "Reads characters until a period (.) character is reached, returns
characters as a string"
  (with-output-to-string (out)
    (loop for character = (read-char stream nil)
       while (and character
                  (not (eq character #\.))) do
         (write-char character out))))

(defun decode (jwt-string &key secret fail-if-unsecured)
  "Decodes and verifies a JSON Web Token. Returns two hash tables,
token claims and token header"
  (with-input-from-string (stream jwt-string)
    (let* ((header-string (read-until-period stream))
           (claims-string (read-until-period stream))
           (digest-string (read-until-period stream))
           (header-hash (yason:parse
                         (octets-to-string
                          (base64-decode
                           header-string)
                          :external-format :utf-8)))
           (claims-hash (yason:parse
                         (octets-to-string
                          (base64-decode
                           claims-string)
                          :external-format :utf-8)))
           (algorithm (gethash "alg" header-hash)))
      ;; Verify HMAC
      (restart-case
          (cond ((equal algorithm "HS256")
                 (compare-HS256-digest header-string
                                       claims-string
                                       secret
                                       digest-string))
                ((or (null algorithm) (equal algorithm "none"))
                 (when fail-if-unsecured
                     (error 'unsecured-token)))
                (t (error 'unsupported-algorithm
                          :algorithm algorithm)))
        (continue () nil))
      ;; Verify timestamps
      (restart-case
          (let ((expires (from-unix-time (gethash "exp" claims-hash)))
                (not-before (from-unix-time (gethash "nbf" claims-hash)))
                (current-time (get-universal-time)))
            (when (and expires (> current-time expires))
              (error 'expired :delta (- current-time expires)))
            (when (and not-before (< current-time not-before))
              (error 'not-yet-valid :delta (- current-time not-before))))
        (continue () nil))
      ;; Return hashes
      (values claims-hash header-hash))))

;;; Conditions

(define-condition unsecured-token (error) ())

(define-condition invalid-hmac (error) ())

(define-condition unsupported-algorithm (error)
  ((algorithm :initarg :algorithm :reader algorithm))
  (:report (lambda (condition stream)
             (format stream "Algorithm \"~A\" not supported"
                     (algorithm condition)))))

(define-condition invalid-time (error)
  ((delta :initarg :delta :reader time-delta))
  (:report (lambda (condition stream)
             (format stream "Token ~A. ~D seconds off."
                     (typecase condition
                       (expired "has expired")
                       (not-yet-valid "is not yet valid"))
                     (time-delta condition)))))

(define-condition expired (invalid-time) ())

(define-condition not-yet-valid (invalid-time) ())
