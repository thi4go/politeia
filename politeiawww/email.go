// Copyright (c) 2018-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"net/url"
	"strings"
	"text/template"
	"time"

	v1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
)

const (
	// GUI routes. These are used in notification emails to direct the
	// user to the correct GUI pages.
	guiRouteProposalDetails  = "/proposals/{token}"
	guirouteProposalComments = "/proposals/{token}/comments/{id}"
	guiRouteRegisterNewUser  = "/register"
	guiRouteDCCDetails       = "/dcc/{token}"
)

func createBody(tpl *template.Template, tplData interface{}) (string, error) {
	var buf bytes.Buffer
	err := tpl.Execute(&buf, tplData)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

func (p *politeiawww) createEmailLink(path, email, token, username string) (string, error) {
	l, err := url.Parse(p.cfg.WebServerAddress + path)
	if err != nil {
		return "", err
	}

	q := l.Query()
	if email != "" {
		q.Set("email", email)
	}
	if token != "" {
		q.Set("verificationtoken", token)
	}
	if username != "" {
		q.Set("username", username)
	}
	l.RawQuery = q.Encode()

	return l.String(), nil
}

// emailNewUserVerificationLink emails the link with the new user verification
// token if the email server is set up.
func (p *politeiawww) emailNewUserVerificationLink(email, token, username string) error {
	link, err := p.createEmailLink(www.RouteVerifyNewUser, email,
		token, username)
	if err != nil {
		return err
	}

	tplData := newUserEmailTemplateData{
		Username: username,
		Email:    email,
		Link:     link,
	}

	subject := "Verify Your Email"
	body, err := createBody(templateNewUserEmail, &tplData)
	if err != nil {
		return err
	}
	recipients := []string{email}

	return p.smtp.sendEmailTo(subject, body, recipients)
}

func (p *politeiawww) newVerificationURL(route, token string) (*url.URL, error) {
	u, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return nil, err
	}

	q := u.Query()
	q.Set("verificationtoken", token)
	u.RawQuery = q.Encode()

	return u, nil
}

// emailResetPasswordVerificationLink emails the link with the reset password
// verification token if the email server is set up.
func (p *politeiawww) emailResetPasswordVerificationLink(email, username, token string) error {
	u, err := p.newVerificationURL(www.RouteResetPassword, token)
	if err != nil {
		return err
	}
	q := u.Query()
	q.Set("username", username)
	u.RawQuery = q.Encode()

	tplData := resetPasswordEmailTemplateData{
		Email: email,
		Link:  u.String(),
	}

	subject := "Reset Your Password"
	body, err := createBody(templateResetPasswordEmail, &tplData)
	if err != nil {
		return err
	}
	recipients := []string{email}

	return p.smtp.sendEmailTo(subject, body, recipients)
}

// emailProposalStatusChange sends emails regarding the proposal status change
// event. Sends email for the author and the users with this notification
// bit set on
func (p *politeiawww) emailProposalStatusChange(data dataProposalStatusChange, emails []string) error {
	route := strings.Replace(guiRouteProposalDetails, "{token}", data.token, 1)
	l, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	// Prepare and send author's email
	err = p.emailAuthorProposalStatusChange(data.name, data.email, l.String(),
		data.statusChangeMessage, data.emailNotifications, data.status, emails)
	if err != nil {
		return err
	}

	// Prepare and send user's email
	err = p.emailUsersProposalStatusChange(data.name, data.username, l.String(),
		emails)
	if err != nil {
		return err
	}

	return nil
}

// emailAuthorProposalStatusChange sends email for the author of the proposal
// in which the status has changed, if his notification bit is set on.
func (p *politeiawww) emailAuthorProposalStatusChange(name, email, link, statusChangeMsg string, emailNotifications uint64, status v1.PropStatusT, emails []string) error {
	if !notificationIsSet(emailNotifications,
		www.NotificationEmailMyProposalStatusChange) {
		return nil
	}

	var subject string
	var template *template.Template

	switch status {
	case v1.PropStatusCensored:
		subject = "Your Proposal Has Been Censored"
		template = templateProposalCensoredForAuthor
	case v1.PropStatusPublic:
		subject = "Your Proposal Has Been Published"
		template = templateProposalVettedForAuthor
	}

	authorTplData := proposalStatusChangeTemplateData{
		Link:               link,
		Name:               name,
		StatusChangeReason: statusChangeMsg,
	}
	body, err := createBody(template, &authorTplData)
	if err != nil {
		return err
	}
	recipients := []string{email}

	return p.smtp.sendEmailTo(subject, body, recipients)
}

// emailUsersProposalStatusChange sends email for all users with this
// notification bit set on.
func (p *politeiawww) emailUsersProposalStatusChange(name, username, link string, emails []string) error {
	if len(emails) > 0 {
		return nil
	}
	subject := "New Proposal Published"
	template := templateProposalVetted
	usersTplData := proposalStatusChangeTemplateData{
		Link:     link,
		Name:     name,
		Username: username,
	}
	body, err := createBody(template, &usersTplData)
	if err != nil {
		return err
	}
	return p.smtp.sendEmailTo(subject, body, emails)
}

// emailProposalEdited sends email regarding the proposal edits event.
// Sends to all users with this notification bit turned on.
func (p *politeiawww) emailProposalEdited(name, username, token, version string, emails []string) error {
	route := strings.Replace(guiRouteProposalDetails, "{token}", token, 1)
	l, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	tplData := proposalEditedTemplateData{
		Link:     l.String(),
		Name:     name,
		Version:  version,
		Username: username,
	}

	subject := "Proposal Edited"
	body, err := createBody(templateProposalEdited, &tplData)
	if err != nil {
		return err
	}

	return p.smtp.sendEmailTo(subject, body, emails)
}

// emailProposalVoteStarted sends email for the proposal vote started event.
// Sends email to author and users with this notification bit set on.
func (p *politeiawww) emailProposalVoteStarted(token, name, username, email string, emailNotifications uint64, emails []string) error {
	route := strings.Replace(guiRouteProposalDetails, "{token}", token, 1)
	l, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	tplData := proposalVoteStartedTemplateData{
		Link:     l.String(),
		Name:     name,
		Username: username,
	}

	if emailNotifications&
		uint64(www.NotificationEmailMyProposalVoteStarted) != 0 {

		subject := "Your Proposal Has Started Voting"
		body, err := createBody(templateProposalVoteStartedForAuthor, &tplData)
		if err != nil {
			return err
		}
		recipients := []string{email}

		err = p.smtp.sendEmailTo(subject, body, recipients)
		if err != nil {
			return err
		}
	}

	subject := "Voting Started for Proposal"
	body, err := createBody(templateProposalVoteStarted, &tplData)
	if err != nil {
		return err
	}

	return p.smtp.sendEmailTo(subject, body, emails)
}

// emailProposalSubmitted sends email notification for a new proposal becoming
// vetted. Sends to the author and for users with this notification setting.
func (p *politeiawww) emailProposalSubmitted(token, name, username string, emails []string) error {
	route := strings.Replace(guiRouteProposalDetails, "{token}", token, 1)
	l, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	tplData := proposalSubmittedTemplateData{
		Link:     l.String(),
		Name:     name,
		Username: username,
	}

	subject := "New Proposal Submitted"
	body, err := createBody(templateProposalSubmitted, &tplData)
	if err != nil {
		return err
	}

	return p.smtp.sendEmailTo(subject, body, emails)
}

// emailProposalVoteAuthorized sends email notification for the proposal vote
// authorized event. Sends to all admins with this notification bit set on.
func (p *politeiawww) emailProposalVoteAuthorized(token, name, username, email string, emails []string) error {
	route := strings.Replace(guiRouteProposalDetails, "{token}", token, 1)
	l, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	tplData := proposalVoteAuthorizedTemplateData{
		Link:     l.String(),
		Name:     name,
		Username: username,
		Email:    email,
	}

	subject := "Proposal Authorized To Start Voting"
	body, err := createBody(templateProposalVoteAuthorized, &tplData)
	if err != nil {
		return err
	}

	return p.smtp.sendEmailTo(subject, body, emails)
}

func (p *politeiawww) emailProposalComment(token, commentID, commentUsername, name, email string) error {
	route := strings.Replace(guirouteProposalComments, "{token}", token, 1)
	route = strings.Replace(route, "{id}", commentID, 1)
	l, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	tplData := commentReplyOnProposalTemplateData{
		Commenter:    commentUsername,
		ProposalName: name,
		CommentLink:  l.String(),
	}

	subject := "New Comment On Your Proposal"
	body, err := createBody(templateCommentReplyOnProposal, &tplData)
	if err != nil {
		return err
	}
	recipients := []string{email}

	return p.smtp.sendEmailTo(subject, body, recipients)
}

// emailUpdateUserKeyVerificationLink emails the link with the verification
// token used for setting a new key pair if the email server is set up.
func (p *politeiawww) emailUpdateUserKeyVerificationLink(email, publicKey, token string) error {
	link, err := p.createEmailLink(www.RouteVerifyUpdateUserKey, "", token, "")
	if err != nil {
		return err
	}

	tplData := updateUserKeyEmailTemplateData{
		Email:     email,
		PublicKey: publicKey,
		Link:      link,
	}

	subject := "Verify Your New Identity"
	body, err := createBody(templateUpdateUserKeyEmail, &tplData)
	if err != nil {
		return err
	}
	recipients := []string{email}

	return p.smtp.sendEmailTo(subject, body, recipients)
}

// emailUserPasswordChanged notifies the user that his password was changed,
// and verifies if he was the author of this action, for security purposes.
func (p *politeiawww) emailUserPasswordChanged(email string) error {
	tplData := userPasswordChangedTemplateData{
		Email: email,
	}

	subject := "Password Changed - Security Verification"
	body, err := createBody(templateUserPasswordChanged, &tplData)
	if err != nil {
		return err
	}
	recipients := []string{email}

	return p.smtp.sendEmailTo(subject, body, recipients)
}

// emailUserLocked notifies the user its account has been locked and emails the
// link with the reset password verification token if the email server is set
// up.
func (p *politeiawww) emailUserLocked(email string) error {
	link, err := p.createEmailLink(ResetPasswordGuiRoute,
		email, "", "")
	if err != nil {
		return err
	}

	tplData := userLockedResetPasswordEmailTemplateData{
		Email: email,
		Link:  link,
	}

	subject := "Locked Account - Reset Your Password"
	body, err := createBody(templateUserLockedResetPassword, &tplData)
	if err != nil {
		return err
	}
	recipients := []string{email}

	return p.smtp.sendEmailTo(subject, body, recipients)
}

// emailInviteNewUserVerificationLink emails the link to invite a user to
// join the Contractor Management System, if the email server is set up.
func (p *politeiawww) emailInviteNewUserVerificationLink(email, token string) error {
	link, err := p.createEmailLink(guiRouteRegisterNewUser, "", token, "")
	if err != nil {
		return err
	}

	tplData := newInviteUserEmailTemplateData{
		Email: email,
		Link:  link,
	}

	subject := "Welcome to the Contractor Management System"
	body, err := createBody(templateInviteNewUserEmail, &tplData)
	if err != nil {
		return err
	}
	recipients := []string{email}

	return p.smtp.sendEmailTo(subject, body, recipients)
}

// emailApproveDCCVerificationLink emails the link to invite a user that
// has been approved by the other contractors from a DCC proposal.
func (p *politeiawww) emailApproveDCCVerificationLink(email string) error {
	tplData := approveDCCUserEmailTemplateData{
		Email: email,
	}

	subject := "Congratulations, You've been approved!"
	body, err := createBody(templateApproveDCCUserEmail, &tplData)
	if err != nil {
		return err
	}
	recipients := []string{email}

	return p.smtp.sendEmailTo(subject, body, recipients)
}

// emailInvoiceNotifications emails users that have not yet submitted an invoice
// for the given month/year
func (p *politeiawww) emailInvoiceNotifications(email, username string) error {
	// Set the date to the first day of the previous month.
	newDate := time.Date(time.Now().Year(), time.Now().Month()-1, 1, 0, 0, 0, 0, time.UTC)
	tplData := invoiceNotificationEmailData{
		Username: username,
		Month:    newDate.Month().String(),
		Year:     newDate.Year(),
	}

	subject := "Awaiting Monthly Invoice"
	body, err := createBody(templateInvoiceNotification, &tplData)
	if err != nil {
		return err
	}
	recipients := []string{email}

	return p.smtp.sendEmailTo(subject, body, recipients)
}

// emailInvoiceComment sends email for the invoice comment event. Sends
// email to the user regarding that invoice.
func (p *politeiawww) emailInvoiceComment(userEmail string) error {
	var tplData interface{}
	subject := "New Invoice Comment"

	body, err := createBody(templateNewInvoiceComment, tplData)
	if err != nil {
		return err
	}
	recipients := []string{userEmail}

	return p.smtp.sendEmailTo(subject, body, recipients)
}

// emailInvoiceStatusUpdate sends email for the invoice status update event.
// Sends email for the user regarding that invoice.
func (p *politeiawww) emailInvoiceStatusUpdate(invoiceToken, userEmail string) error {
	tplData := newInvoiceStatusUpdateTemplate{
		Token: invoiceToken,
	}

	subject := "Invoice status has been updated"
	body, err := createBody(templateNewInvoiceStatusUpdate, &tplData)
	if err != nil {
		return err
	}
	recipients := []string{userEmail}

	return p.smtp.sendEmailTo(subject, body, recipients)
}

// emailDCCNew sends email regarding the DCC New event. Sends email
// to all admins.
func (p *politeiawww) emailDCCNew(token string, emails []string) error {
	route := strings.Replace(guiRouteDCCDetails, "{token}", token, 1)
	l, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	tplData := newDCCSubmittedTemplateData{
		Link: l.String(),
	}

	subject := "New DCC Submitted"
	body, err := createBody(templateNewDCCSubmitted, &tplData)
	if err != nil {
		return err
	}

	return p.smtp.sendEmailTo(subject, body, emails)
}

// emailDCCSupportOppose sends emails regarding dcc support/oppose event.
// Sends emails to all admin users.
func (p *politeiawww) emailDCCSupportOppose(token string, emails []string) error {
	route := strings.Replace(guiRouteDCCDetails, "{token}", token, 1)
	l, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	tplData := newDCCSupportOpposeTemplateData{
		Link: l.String(),
	}

	subject := "New DCC Support/Opposition Submitted"
	body, err := createBody(templateNewDCCSupportOppose, &tplData)
	if err != nil {
		return err
	}

	return p.smtp.sendEmailTo(subject, body, emails)
}
