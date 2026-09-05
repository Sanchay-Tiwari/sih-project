const { parseEmailHeaders } = require('./services/headerParser');
const { getGeoLocation } = require('./services/geoService');

const email = `Delivered-To: sanchaytiwari@bitdurg.ac.in
Received: by 2002:a05:7000:fa07:b0:891:f3f6:9836 with SMTP id cg7csp230860mac; Mon, 31 Aug 2026 09:04:42 -0700 (PDT)
X-Received: by 2002:a17:903:2b04:b0:2c9:d277:2cdb with SMTP id d9443c01a7336-2d91b002e3fmr78461175ad.9.1788192281962; Mon, 31 Aug 2026 09:04:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1788192281; cv=none; d=google.com; s=arc-20260327; b=QTQoWGZY5Hx8utsj7kYZW92z7PxW+I9whdELJr7HPF/d2Lx9WV3lbR+AmdTcBHPw3E vsjafg14P9RrOl8HIyAPMWq4tFTvHBqBombjDM8atqLg6/XGkZz1gkAj3jS1MI93Jc64 m3hDQDcyvqrIN5Q8UAZBD6ifGfiOQMQniEqv1OmT0EbInPJ9hqEssG28g2MeF1njyzWm gz9dRdXGIOPeJxAeFYFKzk9RA7qCNCBmkvkWT/xOs/DZAFA5SNTmqRnc3KX1YifguAsY U/3fvTs4zMgesZihdnrFgmLL/oaiJte28bE+fgf2807gSWtb6+I0Gc1r/g/WVOuCOH92 CYAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20260327; h=feedback-id:mime-version:subject:message-id:to:from:date :dkim-signature:dkim-signature; bh=wvqIxKtFsoi/ueFKDIGdMvUnYzLLj04+WB2KdPoyQm8=; fh=aB1qA+Q1GrO2zTK2XzLm2TuDh0uGoCi3JhmZ0XupU7Q=; b=S41iovoRWwRq1ik4gTAnNyP1Vz9eYcsG8UXD7GuL6DhfvZE9aqBCCMHnpie9Nb/aaw 1wDnMoZPrlqU/jSnhCJZpSP30g5KrqUgfOJDR+ynKVVfrtmmb4VF1RgI9+PeJsAyKVzR MpIxNX9zDfDUFlmR1E3Nih6ALeAdSDUGrH8qw8Fij+mk0igtgWteQcy7uctfDryY9X6Z q1yuxgehQQACPApbflhkAdJLMXLgWf/rpjOtabHaxbDLHzJRDTYSiKqsGR64QXv01TCI WOXbmrDpsJnfpPU0ox7cWwlC4xRteLjXyzZnCVGlrLgmYM2ivt5xY85PoAigz92KJk14 cVjQ==; dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; dkim=pass header.i=@swiggy.in header.s=s3iljnim4erhcwkgkf3ni3fxz4564fvd header.b=WQRk5QaE; dkim=pass header.i=@amazonses.com header.s=hsbnp7p3ensaochzwyq5wwmceodymuwv header.b=rA2MQCnf; spf=pass (google.com: domain of 010101a05890d27b-9258ddaf-20db-48a8-a647-9e1468dfb645-000000@us-west-2.amazonses.com designates 54.240.27.99 as permitted sender) smtp.mailfrom=010101a05890d27b-9258ddaf-20db-48a8-a647-9e1468dfb645-000000@us-west-2.amazonses.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=swiggy.in
Return-Path: <010101a05890d27b-9258ddaf-20db-48a8-a647-9e1468dfb645-000000@us-west-2.amazonses.com>
Received: from a27-99.smtp-out.us-west-2.amazonses.com (a27-99.smtp-out.us-west-2.amazonses.com. [54.240.27.99]) by mx.google.com with ESMTPS id d9443c01a7336-2d7598d4140si190069105ad.137.2026.08.31.09.04.41 for <sanchaytiwari@bitdurg.ac.in> (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128); Mon, 31 Aug 2026 09:04:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of 010101a05890d27b-9258ddaf-20db-48a8-a647-9e1468dfb645-000000@us-west-2.amazonses.com designates 54.240.27.99 as permitted sender) client-ip=54.240.27.99;
Authentication-Results: mx.google.com; dkim=pass header.i=@swiggy.in header.s=s3iljnim4erhcwkgkf3ni3fxz4564fvd header.b=WQRk5QaE; dkim=pass header.i=@amazonses.com header.s=hsbnp7p3ensaochzwyq5wwmceodymuwv header.b=rA2MQCnf; spf=pass (google.com: domain of 010101a05890d27b-9258ddaf-20db-48a8-a647-9e1468dfb645-000000@us-west-2.amazonses.com designates 54.240.27.99 as permitted sender) smtp.mailfrom=010101a05890d27b-9258ddaf-20db-48a8-a647-9e1468dfb645-000000@us-west-2.amazonses.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=swiggy.in
From: swiggyforstudents@swiggy.in
To: sanchaytiwari@bitdurg.ac.in
Subject: Verify for Swiggy
Date: Mon, 31 Aug 2026 16:04:41 +0000
Code: 195495`;

async function main() {
    try {
        const p = await parseEmailHeaders(email);
        console.log("Extracted Hop IP Chain:", p.hopIPChain);
        console.log("Extracted Originating IP:", p.originatingIP);
        const geo = await getGeoLocation(p.originatingIP);
        console.log("Geo Result:", geo);
    } catch (e) {
        console.error("Error:", e);
    }
}

main();

